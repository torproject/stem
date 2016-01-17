package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"git.torproject.org/user/phw/zoossh.git"
)

var processedCons int64 = 0
var processedDescs int64 = 0
var totalExits int64 = 0
var totalRelays int64 = 0
var totalBw uint64 = 0

func Min(a uint64, b uint64, c uint64) uint64 {

	min := a

	if b < min {
		min = b
	}

	if c < min {
		min = c
	}

	return min
}

func ProcessDescriptors(path string, info os.FileInfo, err error) error {

	if _, err := os.Stat(path); err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	consensus, err := zoossh.ParseDescriptorFile(path)
	if err != nil {
		return err
	}

	if (processedDescs % 100) == 0 {
		fmt.Printf(".")
	}

	for _, getDesc := range consensus.RouterDescriptors {
		desc := getDesc()
		totalBw += Min(desc.BandwidthAvg, desc.BandwidthBurst, desc.BandwidthObs)
		processedDescs++
	}

	return nil
}

func ProcessConsensus(path string, info os.FileInfo, err error) error {

	if _, err := os.Stat(path); err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	consensus, err := zoossh.ParseConsensusFile(path)
	if err != nil {
		return err
	}
	fmt.Printf(".")

	for _, getStatus := range consensus.RouterStatuses {
		status := getStatus()
		totalRelays++
		if status.Flags.Exit == true {
			totalExits++
		}
	}
	processedCons++

	return nil
}

func main() {

	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s CONSENSUS_ARCHIVE DESCRIPTOR_ARCHIVE", os.Args[0])
	}

	before := time.Now()
	filepath.Walk(os.Args[1], ProcessConsensus)
	fmt.Println()
	after := time.Now()

	duration := after.Sub(before)
	fmt.Println("Total time for consensuses:", duration)
	fmt.Printf("Time per consensus: %dms\n",
		duration.Nanoseconds()/processedCons/int64(1000000))
	fmt.Printf("Processed %d consensuses with %d router status entries.\n",
		processedCons, totalRelays)
	fmt.Printf("Total exits: %d\n", totalExits)

	before = time.Now()
	filepath.Walk(os.Args[2], ProcessDescriptors)
	fmt.Println()
	after = time.Now()

	duration = after.Sub(before)
	fmt.Println("Total time for descriptors:", duration)
	fmt.Printf("Time per descriptor: %dns\n",
		duration.Nanoseconds()/processedDescs)
	fmt.Printf("Processed %d descriptors.\n", processedDescs)
	fmt.Printf("Average advertised bandwidth: %d\n", totalBw/uint64(processedDescs))
}
