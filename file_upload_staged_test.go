package proton_api_bridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/henrybear327/Proton-API-Bridge/common"
)

func newStagedTestDrive(t *testing.T, cutoff, minFree int64) (*ProtonDrive, string) {
	t.Helper()
	root := t.TempDir()
	return &ProtonDrive{
		Config: &common.Config{
			StagedUploadCutoffBytes:  cutoff,
			StagedUploadDir:          root,
			StagedUploadMinFreeBytes: minFree,
			StagedUploadMaxRounds:    5,
		},
	}, root
}

func TestPrepareStagedUploadCutoff(t *testing.T) {
	pd, root := newStagedTestDrive(t, 1<<30, 0)

	// below cutoff -> streaming
	if _, ok := pd.prepareStagedUpload(1 << 20); ok {
		t.Fatal("expected streaming pipeline below cutoff")
	}
	// unknown size -> streaming
	if _, ok := pd.prepareStagedUpload(-1); ok {
		t.Fatal("expected streaming pipeline for unknown size")
	}
	// cutoff disabled -> streaming
	pd.Config.StagedUploadCutoffBytes = 0
	if _, ok := pd.prepareStagedUpload(10 << 30); ok {
		t.Fatal("expected streaming pipeline when staging disabled")
	}

	// at/above cutoff -> staged, dir created under root
	pd.Config.StagedUploadCutoffBytes = 1 << 30
	dir, ok := pd.prepareStagedUpload(1 << 30)
	if !ok {
		t.Fatal("expected staged pipeline at cutoff")
	}
	if filepath.Dir(dir) != root {
		t.Fatalf("staging dir %q not under root %q", dir, root)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("staging dir not created: %v", err)
	}
}

func TestPrepareStagedUploadFreeSpaceGate(t *testing.T) {
	// Demand an absurd headroom so the gate must reject and fall back.
	pd, _ := newStagedTestDrive(t, 1<<30, 1<<60)
	if _, ok := pd.prepareStagedUpload(1 << 30); ok {
		t.Fatal("expected fallback to streaming when free-space gate fails")
	}
}

func TestCleanupStaleStagingDirs(t *testing.T) {
	root := t.TempDir()

	stale := filepath.Join(root, stagedDirPrefix+"stale")
	fresh := filepath.Join(root, stagedDirPrefix+"fresh")
	unrelated := filepath.Join(root, "keep-me")
	for _, d := range []string{stale, fresh, unrelated} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-stagedStaleAge - time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	cleanupStaleStagingDirs(root)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale staging dir should have been removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh staging dir should have been kept")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated dir should have been kept")
	}
}

func TestDiskAvail(t *testing.T) {
	if avail := diskAvail(t.TempDir()); avail <= 0 {
		t.Fatalf("expected positive disk avail, got %d", avail)
	}
	if avail := diskAvail(filepath.Join(t.TempDir(), "does-not-exist")); avail != -1 {
		t.Fatalf("expected -1 for missing path, got %d", avail)
	}
}

// TestEncryptToStaging exercises phase 1 of the staged pipeline end-to-end
// with locally generated keys: the source stream must be split, encrypted,
// verified and staged to disk with consistent metadata, and every staged
// block must decrypt back to the original plaintext.
func TestEncryptToStaging(t *testing.T) {
	key, err := crypto.GenerateKey("test", "test@example.com", "x25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	pd := &ProtonDrive{
		DefaultAddrKR: kr,
		Config:        &common.Config{},
	}

	// 2.5 blocks worth of data to get a partial trailing block
	src := make([]byte, UPLOAD_BLOCK_SIZE*2+UPLOAD_BLOCK_SIZE/2)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	verifCode := make([]byte, 16)
	if _, err := rand.Read(verifCode); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// The verifier session key is the content session key in production;
	// reuse sessionKey so verifyBlock's decrypt check passes.
	blocks, manifest, totalSize, blockSizes, sha1String, err := pd.encryptToStaging(
		context.Background(), sessionKey, kr, bytes.NewReader(src), verifCode, sessionKey, dir)
	if err != nil {
		t.Fatal(err)
	}

	if totalSize != int64(len(src)) {
		t.Fatalf("totalSize = %d, want %d", totalSize, len(src))
	}
	if len(blocks) != 3 || len(blockSizes) != 3 {
		t.Fatalf("expected 3 blocks, got %d (sizes %d)", len(blocks), len(blockSizes))
	}
	if blockSizes[2] != int64(UPLOAD_BLOCK_SIZE/2) {
		t.Fatalf("trailing block size = %d, want %d", blockSizes[2], UPLOAD_BLOCK_SIZE/2)
	}
	wantSha1 := sha1.Sum(src)
	if sha1String != hex.EncodeToString(wantSha1[:]) {
		t.Fatal("sha1 mismatch")
	}
	if len(manifest) != 32*len(blocks) {
		t.Fatalf("manifest length = %d, want %d", len(manifest), 32*len(blocks))
	}

	// every staged block decrypts back to the original chunk
	var recovered []byte
	for i, b := range blocks {
		if b.info.Index != i+1 {
			t.Fatalf("block %d has index %d", i, b.info.Index)
		}
		encData, err := os.ReadFile(b.path)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(encData)) != b.info.Size {
			t.Fatalf("block %d: file size %d != meta size %d", i, len(encData), b.info.Size)
		}
		plain, err := sessionKey.Decrypt(encData)
		if err != nil {
			t.Fatalf("block %d does not decrypt: %v", i, err)
		}
		recovered = append(recovered, plain.GetBinary()...)
	}
	if !bytes.Equal(recovered, src) {
		t.Fatal("recovered plaintext differs from source")
	}
}
