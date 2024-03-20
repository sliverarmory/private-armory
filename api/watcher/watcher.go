package watcher

import "errors"

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

var (
	ErrWatcherNotInitialized = errors.New("the watcher is not initialized")
)

// An empty interface for holding watcher options. These can be anything - it
// depends on the watcher.
type WatcherOptions interface{}

type Watcher interface {
	// Set up a new instance of the Watcher
	New(WatcherOptions) error
	// Add a path (base path and object / file path) to watch, returns a nil error on success
	Add(string, string) error
	// Returns whether the watcher has been successfully initialized
	Initialized() bool
	// Return a slice of the paths that the watcher is monitoring
	Paths() []string
	// Return the event channel that sends a notification when an event has occurred
	// Returns an error if the Watcher has not been initialized
	EventChannel() (chan string, error)
	// Return the error channel that sends a notification when an error has occurred
	// Returns an error if the Watcher has not been initialized
	ErrorChannel() (chan error, error)
	// Performs any functions necessary to cleanly shutdown the watcher
	Close()
}
