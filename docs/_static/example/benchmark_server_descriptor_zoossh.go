package main

import (
  "fmt"
  "os"
  "path/filepath"
  "time"

  "git.torproject.org/user/phw/zoossh.git"
)

var processedDescs int64 = 0
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

func main() {
  before = time.Now()
  filepath.Walk("server-descriptors-2015-11", ProcessDescriptors)
  fmt.Println()
  after = time.Now()

  duration = after.Sub(before)
  fmt.Println("Total time for descriptors:", duration)
  fmt.Printf("Time per descriptor: %dns\n",
    duration.Nanoseconds()/processedDescs)
  fmt.Printf("Processed %d descriptors.\n", processedDescs)
  fmt.Printf("Average advertised bandwidth: %d\n", totalBw/uint64(processedDescs))
}
