package watcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
)

/*
	Sliver Implant Framework
	Copyright (C) 2024  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
	S3 does not have a concept of events when a change occurs, so this package
	is necessary to monitor changes to packages in the armory. Because there
	are no events to catch, this package polls the bucket(s) it is watching.
	The polling interval is configurable when spinning up the watcher. There
	is no default interval, so one must be specified.

	This package requires the s3:GetObject and s3:ListBucket permissions
	in order to function.

	The watcher calculates a hash of all eTags for the objects it is monitoring.
	This is called the state hash. If an object is created, removed, or changed,
	the eTag for that object will change and therefore change the hash of the
	collection of eTags.

	If the state hash changes between updates, the watcher emits an event through
	its event channel to signal that the index needs to be refreshed. The reason for
	this approach is that we do not need to know *what* change has occurred,
	only *that* a change has occurred. Otherwise, we would have to track
	each object individually, and that could get unwieldy with large
	numbers of objects.
*/

type S3WatcherOptions struct {
	// The configured S3 client from the caller
	S3Client *s3.Client
	// The polling interval in seconds (must be greater than 0)
	PollTimeSeconds uint
}

type S3Watcher struct {
	// The client to interact with S3
	s3Client *s3.Client
	// A boolean representing whether the watcher was successfully created and that it is ready to go
	initialized bool
	// These are paths added by the user - keyed by bucket
	paths map[string][]string
	// S3 does not have events when an object is changed, so we will have to poll
	pollTime time.Duration
	// A channel to send an event when there is an update in the monitored paths
	eventChannel chan string
	// A channel to communicate errors
	errorChannel chan error
	// A channel to signal shutdown
	doneChannel chan struct{}
	// A hash representing the current state of the bucket with respect to the objects we are tracking
	stateHash []byte
}

// Lists the objects in the bucket with given prefixes so that we know which objects we need to get
// eTags for
func (sw *S3Watcher) getObjectsInBucket(bucketName string, prefixes []string) ([]string, error) {
	objectKeys := []string{}

	for _, prefix := range prefixes {
		objectListParameters := &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
			Prefix: aws.String(prefix),
		}

		listResult, err := sw.s3Client.ListObjectsV2(context.TODO(), objectListParameters)
		if err != nil {
			return nil, err
		}
		if *listResult.IsTruncated {
			for *listResult.IsTruncated {
				for _, entry := range listResult.Contents {
					objectKeys = append(objectKeys, *entry.Key)
				}
				objectListParameters.ContinuationToken = listResult.ContinuationToken
				listResult, err = sw.s3Client.ListObjectsV2(context.TODO(), objectListParameters)
				if err != nil {
					return nil, err
				}
			}
		}

		for _, entry := range listResult.Contents {
			objectKeys = append(objectKeys, *entry.Key)
		}
	}

	return objectKeys, nil
}

// Get the eTag for an object
func (sw *S3Watcher) getETagForObject(bucket, key string) (string, error) {
	headObjectParameters := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := sw.s3Client.HeadObject(context.TODO(), headObjectParameters)
	if err != nil {
		return "", err
	}
	return *result.ETag, nil
}

// Get eTags for all tracked objects and hash them to determine if there has been a
// change in the bucket(s). If there has, return true. Returns false if there has
// not been an update.
func (sw *S3Watcher) checkForUpdates() bool {
	sendEvent := false
	hasher := sha256.New()
	// Get a list of all objects in the buckets we are monitoring
	for bucket, objectKeys := range sw.paths {
		matchingObjectKeys, err := sw.getObjectsInBucket(bucket, objectKeys)
		if err != nil {
			// Send an error down the channel and keep going
			sw.errorChannel <- fmt.Errorf("could not get objects in bucket %s: %s", bucket, err)
			continue
		}
		for _, key := range matchingObjectKeys {
			// Get ETag for each object key
			fullPath := fmt.Sprintf("%s/%s", bucket, key)
			eTag, err := sw.getETagForObject(bucket, key)
			if err != nil {
				// Send an error down the channel and keep going
				sw.errorChannel <- fmt.Errorf("error getting info about %s: %s", fullPath, err)
				continue
			}
			hasher.Write([]byte(eTag))
		}
	}
	currentHash := hasher.Sum(nil)
	sendEvent = !bytes.Equal(sw.stateHash, currentHash)
	sw.stateHash = currentHash
	return sendEvent
}

// Until it is told to stop, the watcher will check for updates at each poll interval
func (sw *S3Watcher) watchPaths() {
	if !sw.initialized {
		return
	}

	defer close(sw.eventChannel)
	defer close(sw.errorChannel)
	defer close(sw.doneChannel)

	ticker := time.NewTicker(sw.pollTime)

	for {
		select {
		case <-ticker.C:
			sendEvent := sw.checkForUpdates()
			if sendEvent {
				sw.eventChannel <- "Update in monitored S3 objects"
			}
		case <-sw.doneChannel:
			ticker.Stop()
			return
		}
	}
}

// Initialize the watcher
func (sw *S3Watcher) New(options WatcherOptions) error {
	s3Options, ok := options.(S3WatcherOptions)
	if !ok {
		return errors.New("invalid options provided")
	}

	if s3Options.PollTimeSeconds == 0 {
		return errors.New("poll time must be greater than 0 seconds")
	}

	sw.s3Client = s3Options.S3Client
	sw.pollTime = time.Duration(s3Options.PollTimeSeconds) * time.Second

	sw.eventChannel = make(chan string)
	sw.errorChannel = make(chan error)
	sw.doneChannel = make(chan struct{})

	sw.paths = make(map[string][]string)

	sw.initialized = true
	go sw.watchPaths()

	return nil
}

// Add a path to the watcher which consists of a bucket and prefix
// (what the path must start with). The prefix should not start
// with a forward slash (/). The prefix does not have to exist
// in the bucket. Returns an error if the watcher is not initialized.
func (sw *S3Watcher) Add(bucketName, objectPath string) error {
	if !sw.initialized {
		return ErrWatcherNotInitialized
	}

	objectPath = strings.TrimPrefix(objectPath, "/")

	/*
		If an object does not yet exist, that is okay. We can
		keep looking for it in the main loop.
		When the server is initially set up, objects in the
		extensions and aliases paths will not exist.
	*/
	pathsForBucket, ok := sw.paths[bucketName]
	if !ok {
		sw.paths[bucketName] = []string{objectPath}
	} else {
		if !slices.Contains(pathsForBucket, objectPath) {
			pathsForBucket = append(pathsForBucket, objectPath)
			sw.paths[bucketName] = pathsForBucket
		}
	}

	return nil
}

// Returns the full path of objects monitored by the watcher.
// The full path is bucket/prefix. If the watcher is not initalized,
// an empty string slice is returned.
func (sw *S3Watcher) Paths() []string {
	monitoredPaths := []string{}
	if !sw.initialized {
		return monitoredPaths
	}

	for bucket, objectPaths := range sw.paths {
		for _, path := range objectPaths {
			fullPath := fmt.Sprintf("%s/%s", bucket, path)
			monitoredPaths = append(monitoredPaths, fullPath)
		}
	}

	return monitoredPaths
}

// Returns the watcher's event channel. Only returns an error if the
// watcher is not initialized
func (sw *S3Watcher) EventChannel() (chan string, error) {
	if !sw.initialized {
		return nil, ErrWatcherNotInitialized
	}

	return sw.eventChannel, nil
}

// Returns the watcher's error channel. Only returns an error if the
// watcher is not initialized
func (sw *S3Watcher) ErrorChannel() (chan error, error) {
	if !sw.initialized {
		return nil, ErrWatcherNotInitialized
	}

	return sw.errorChannel, nil
}

// Instructs the main loop to stop
func (sw *S3Watcher) Close() {
	if !sw.initialized {
		return
	}
	// Signal through the done channel to stop the update loop
	sw.doneChannel <- struct{}{}
	sw.initialized = false
}
