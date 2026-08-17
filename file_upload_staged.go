package proton_api_bridge

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/henrybear327/go-proton-api"
)

/*
Staged upload pipeline, modelled after the official macOS client
(PDCore FileUploader: DiscreteBlocksRevisionEncryptor -> PaginatedRevisionUploader
-> RetryPageRevisionUploader -> RevisionCommitter):

 1. encrypt the whole source stream to per-block files on local disk
    (the source reader is consumed exactly once, no matter what happens later)
 2. upload the staged blocks; failed blocks are retried in later rounds with
    freshly requested upload URLs and exponential backoff, never touching the
    source stream again
 3. commit the revision (done by the caller)

This makes a transient block-upload failure recoverable without re-reading the
source, which is essential when the source is a remote, non-seekable stream.
*/

const (
	stagedDirPrefix     = "up-"
	stagedStaleAge      = 48 * time.Hour
	stagedBlockFileMode = 0o600
	stagedDirMode       = 0o700
)

type stagedBlock struct {
	info     proton.BlockUploadInfo
	hash     []byte // raw sha256 of the encrypted block (manifest material)
	path     string // encrypted block file on disk
	uploaded bool
}

// stagingRoot resolves the root directory that holds per-upload staging dirs.
func (protonDrive *ProtonDrive) stagingRoot() string {
	if protonDrive.Config.StagedUploadDir != "" {
		return protonDrive.Config.StagedUploadDir
	}
	return filepath.Join(os.TempDir(), "proton-api-bridge-staged")
}

// cleanupStaleStagingDirs removes leftover per-upload dirs from crashed or
// killed processes. Best effort: errors are ignored.
func cleanupStaleStagingDirs(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), stagedDirPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > stagedStaleAge {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// prepareStagedUpload decides whether the staged pipeline should be used for a
// file of knownSize and, if so, creates the per-upload staging directory.
// Falling back to the streaming pipeline is always safe, so any failure here
// simply returns ok=false.
func (protonDrive *ProtonDrive) prepareStagedUpload(knownSize int64) (string, bool) {
	cutoff := protonDrive.Config.StagedUploadCutoffBytes
	if cutoff <= 0 || knownSize < 0 || knownSize < cutoff {
		return "", false
	}

	root := protonDrive.stagingRoot()
	if err := os.MkdirAll(root, stagedDirMode); err != nil {
		return "", false
	}

	cleanupStaleStagingDirs(root)

	// Free-space gate: the staged copy needs roughly the file size (PGP adds
	// ~0.1% per 4 MiB block; 1/64 is a generous allowance) plus the configured
	// headroom so staging can never fill up the disk.
	if avail := diskAvail(root); avail >= 0 {
		need := knownSize + knownSize/64 + protonDrive.Config.StagedUploadMinFreeBytes
		if avail < need {
			return "", false
		}
	}

	dir, err := os.MkdirTemp(root, stagedDirPrefix)
	if err != nil {
		return "", false
	}
	return dir, true
}

// encryptToStaging consumes the source stream once: each UPLOAD_BLOCK_SIZE
// chunk is encrypted, verified and written to its own file under stagingDir.
// Mirrors the metadata collection of the streaming pipeline exactly.
func (protonDrive *ProtonDrive) encryptToStaging(
	ctx context.Context,
	newSessionKey *crypto.SessionKey, newNodeKR *crypto.KeyRing,
	file io.Reader,
	verifCode []byte, verifierSK *crypto.SessionKey,
	stagingDir string,
) (blocks []*stagedBlock, manifestSignatureData []byte, totalFileSize int64, blockSizes []int64, sha1String string, err error) {
	sha1Digests := sha1.New()
	manifestSignatureData = make([]byte, 0)
	blockSizes = make([]int64, 0)

	shouldContinue := true
	for i := 1; shouldContinue; i++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, nil, "", err
		}

		// read at most data of size UPLOAD_BLOCK_SIZE
		// for some reason, .Read might not actually read up to buffer size -> use io.ReadFull
		data := make([]byte, UPLOAD_BLOCK_SIZE) // FIXME: get block size from the server config instead of hardcoding it
		readBytes, err := io.ReadFull(file, data)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// might still have data to read!
				if readBytes == 0 {
					break
				}
				shouldContinue = false
			} else {
				// all other errors
				return nil, nil, 0, nil, "", err
			}
		}
		data = data[:readBytes]
		totalFileSize += int64(readBytes)
		sha1Digests.Write(data)
		blockSizes = append(blockSizes, int64(readBytes))

		// encrypt block data
		/*
			Encryption: current link's session key
			Signature: share's signature address keys
		*/
		dataPlainMessage := crypto.NewPlainMessage(data)
		encData, err := newSessionKey.Encrypt(dataPlainMessage)
		if err != nil {
			return nil, nil, 0, nil, "", err
		}

		encSignature, err := protonDrive.DefaultAddrKR.SignDetachedEncrypted(dataPlainMessage, newNodeKR)
		if err != nil {
			return nil, nil, 0, nil, "", err
		}
		encSignatureStr, err := encSignature.GetArmored()
		if err != nil {
			return nil, nil, 0, nil, "", err
		}

		h := sha256.New()
		h.Write(encData)
		hash := h.Sum(nil)
		manifestSignatureData = append(manifestSignatureData, hash...)

		verificationToken, err := verifyBlock(verifCode, verifierSK, encData)
		if err != nil {
			return nil, nil, 0, nil, "", err
		}

		blockPath := filepath.Join(stagingDir, fmt.Sprintf("block-%06d.enc", i))
		if err := os.WriteFile(blockPath, encData, stagedBlockFileMode); err != nil {
			return nil, nil, 0, nil, "", err
		}

		blocks = append(blocks, &stagedBlock{
			info: proton.BlockUploadInfo{
				Index:        i, // iOS drive: BE starts with 1
				Size:         int64(len(encData)),
				EncSignature: encSignatureStr,
				Hash:         base64.StdEncoding.EncodeToString(hash),
				Verifier: proton.Verifier{
					Token: verificationToken,
				},
			},
			hash: hash,
			path: blockPath,
		})
	}

	sha1Hash := sha1Digests.Sum(nil)
	return blocks, manifestSignatureData, totalFileSize, blockSizes, hex.EncodeToString(sha1Hash), nil
}

// uploadStagedBatch requests upload URLs for one batch of blocks and uploads
// them concurrently. Individual block failures don't abort the batch: failed
// blocks stay pending for the next round. Returns the number of blocks
// uploaded and the first error encountered (if any).
func (protonDrive *ProtonDrive) uploadStagedBatch(ctx context.Context, batch []*stagedBlock, linkID, revisionID string) (int, error) {
	blockList := make([]proton.BlockUploadInfo, 0, len(batch))
	for _, b := range batch {
		blockList = append(blockList, b.info)
	}
	blockUploadResp, err := protonDrive.c.RequestBlockUpload(ctx, proton.BlockUploadReq{
		AddressID:  protonDrive.MainShare.AddressID,
		ShareID:    protonDrive.MainShare.ShareID,
		LinkID:     linkID,
		RevisionID: revisionID,

		BlockList: blockList,
	})
	if err != nil {
		return 0, err
	}
	if len(blockUploadResp) != len(batch) {
		return 0, fmt.Errorf("staged upload: requested %d upload URLs, got %d", len(batch), len(blockUploadResp))
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		okCount  int
	)
	for i := range batch {
		wg.Add(1)
		go func(b *stagedBlock, bareURL, token string) {
			defer wg.Done()

			if err := protonDrive.blockUploadSemaphore.Acquire(ctx, 1); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			defer protonDrive.blockUploadSemaphore.Release(1)

			encData, err := os.ReadFile(b.path)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			// Quick in-place retries for transient blips; a fresh
			// bytes.Reader per attempt (resty cannot replay a consumed
			// reader). Anything that still fails is left for the next round,
			// which re-requests URLs and backs off exponentially.
			const maxRetries = 3
			var lastErr error
			for attempt := 0; attempt <= maxRetries; attempt++ {
				if ctx.Err() != nil {
					lastErr = ctx.Err()
					break
				}
				lastErr = protonDrive.c.UploadBlock(ctx, bareURL, token, bytes.NewReader(encData))
				if lastErr == nil {
					mu.Lock()
					okCount++
					mu.Unlock()
					b.uploaded = true
					return
				}
				if attempt < maxRetries {
					time.Sleep(time.Duration(attempt+1) * time.Second)
				}
			}
			mu.Lock()
			if firstErr == nil {
				firstErr = lastErr
			}
			mu.Unlock()
		}(batch[i], blockUploadResp[i].BareURL, blockUploadResp[i].Token)
	}
	wg.Wait()

	return okCount, firstErr
}

// uploadStagedBlocks drives upload rounds over the staged blocks until all are
// uploaded, the rounds budget is exhausted, or the context is cancelled.
// Equivalent of the macOS client's PaginatedRevisionUploader (skip uploaded
// blocks) + RetryPageRevisionUploader (bounded retries with backoff+jitter).
func (protonDrive *ProtonDrive) uploadStagedBlocks(ctx context.Context, blocks []*stagedBlock, linkID, revisionID string) error {
	maxRounds := protonDrive.Config.StagedUploadMaxRounds
	if maxRounds <= 0 {
		maxRounds = 1
	}

	var lastErr error
	for round := 0; round < maxRounds; round++ {
		pending := make([]*stagedBlock, 0)
		for _, b := range blocks {
			if !b.uploaded {
				pending = append(pending, b)
			}
		}
		if len(pending) == 0 {
			return nil
		}

		if round > 0 {
			// Exponential backoff with jitter (macOS client uses the same
			// shape with a 10 min cap; 60 s is plenty for a server process).
			delay := time.Duration(1<<uint(round-1)) * time.Second
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			delay += time.Duration(rand.Intn(1000)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		uploadedThisRound := 0
		for start := 0; start < len(pending); start += UPLOAD_BATCH_BLOCK_SIZE {
			if err := ctx.Err(); err != nil {
				return err
			}
			end := start + UPLOAD_BATCH_BLOCK_SIZE
			if end > len(pending) {
				end = len(pending)
			}
			okCount, err := protonDrive.uploadStagedBatch(ctx, pending[start:end], linkID, revisionID)
			uploadedThisRound += okCount
			if err != nil {
				lastErr = err
				if okCount == 0 {
					// Nothing in this batch went through (e.g. throttled or
					// URL request failed) - stop hammering, keep the rest for
					// the next round after backoff.
					break
				}
			}
		}

		if uploadedThisRound == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
	}

	remaining := 0
	for _, b := range blocks {
		if !b.uploaded {
			remaining++
		}
	}
	if remaining > 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("staged upload: %d block(s) still pending", remaining)
		}
		return fmt.Errorf("staged upload: %d block(s) failed after %d round(s): %w", remaining, maxRounds, lastErr)
	}
	return nil
}

// uploadAndCollectBlockDataStaged is the staged counterpart of
// uploadAndCollectBlockData: same inputs and outputs, but the source stream is
// fully encrypted to stagingDir before any block is uploaded. Owns stagingDir
// and removes it on all paths.
func (protonDrive *ProtonDrive) uploadAndCollectBlockDataStaged(
	ctx context.Context,
	newSessionKey *crypto.SessionKey, newNodeKR *crypto.KeyRing,
	file io.Reader,
	linkID, revisionID string,
	stagingDir string,
) ([]byte, int64, []int64, string, error) {
	defer func() {
		_ = os.RemoveAll(stagingDir)
	}()

	if newSessionKey == nil || newNodeKR == nil {
		return nil, 0, nil, "", ErrMissingInputUploadAndCollectBlockData
	}

	//verification
	res, err := protonDrive.c.Verification(ctx, protonDrive.MainShare.ShareID, linkID, revisionID)
	if err != nil {
		return nil, 0, nil, "", err
	}

	pktBytes, err := base64.StdEncoding.DecodeString(res.ContentKeyPacket)
	if err != nil {
		return nil, 0, nil, "", err
	}

	// Use the node keyring / private keyring to decrypt the session key
	verifierSK, err := newNodeKR.DecryptSessionKey(crypto.NewPGPMessage(pktBytes).Data)
	if err != nil {
		return nil, 0, nil, "", err
	}

	verifCode, err := base64.StdEncoding.DecodeString(res.VerificationCode)
	if err != nil {
		return nil, 0, nil, "", err
	}

	/* phase 1: encrypt the whole stream to disk (source consumed exactly once) */
	blocks, manifestSignatureData, totalFileSize, blockSizes, sha1String, err := protonDrive.encryptToStaging(ctx, newSessionKey, newNodeKR, file, verifCode, verifierSK, stagingDir)
	if err != nil {
		return nil, 0, nil, "", err
	}

	/* phase 2: upload from disk, with per-block bookkeeping and retry rounds */
	if err := protonDrive.uploadStagedBlocks(ctx, blocks, linkID, revisionID); err != nil {
		return nil, 0, nil, "", err
	}

	return manifestSignatureData, totalFileSize, blockSizes, sha1String, nil
}
