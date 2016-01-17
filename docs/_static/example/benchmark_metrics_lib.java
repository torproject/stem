/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedMap;

public class MeasurePerformance {

  /* Check if all necessary files are available and then measure
   * performance of some more or less common use cases. */
  public static void main(String[] args) {
    if (!filesAvailable()) {
      return;
    }
    /*measureListOutdatedRelays(null);
    pause();*/
    measureAverageAdvertisedBandwidth(new File(resDir, resPaths[0]));
    pause();
    measureAverageAdvertisedBandwidth(new File(resDir, resPaths[1]));
    pause();
    measureAverageAdvertisedBandwidth(new File(resDir, resPaths[2]));
    pause();
    /*measureFractionRelaysExit80ServerDescriptors(null);
    pause();
    measureSumOfWrittenAndReadBytes(null);
    pause();*/
    measureCountriesV3Requests(new File(resDir, resPaths[3]));
    pause();
    measureCountriesV3Requests(new File(resDir, resPaths[4]));
    pause();
    measureAverageRelaysExit(new File(resDir, resPaths[5]));
    pause();
    measureAverageRelaysExit(new File(resDir, resPaths[6]));
    pause();
    measureAverageRelaysExit(new File(resDir, resPaths[7]));
    /*pause();
    measureVotesByBandwidthAuthorities(null);
    pause();
    measureExtendedFamilies(null);
    pause();*/
    measureFractionRelaysExit80Microdescriptors(
        new File(resDir, resPaths[8]));
    measureFractionRelaysExit80Microdescriptors(
        new File(resDir, resPaths[9]));
  }

  private static File resDir = new File("res");
  private static String[] resPaths = new String[] {
    "archive/relay-descriptors/server-descriptors/"
        + "server-descriptors-2015-11.tar.xz",
    "archive/relay-descriptors/server-descriptors/"
        + "server-descriptors-2015-11.tar",
    "archive/relay-descriptors/server-descriptors/"
        + "server-descriptors-2015-11",
    "archive/relay-descriptors/extra-infos/extra-infos-2015-11.tar.xz",
    "archive/relay-descriptors/extra-infos/extra-infos-2015-11.tar",
    "archive/relay-descriptors/consensuses/consensuses-2015-11.tar.xz",
    "archive/relay-descriptors/consensuses/consensuses-2015-11.tar",
    "archive/relay-descriptors/consensuses/consensuses-2015-11",
    "archive/relay-descriptors/microdescs/"
        + "microdescs-2015-11-micro.tar.xz",
    "archive/relay-descriptors/microdescs/microdescs-2015-11-micro.tar"
  };

  private static boolean filesAvailable() {
    if (!resDir.exists() || !resDir.isDirectory()) {
      return false;
    }
    for (String resPath : resPaths) {
      if (!(new File(resDir, resPath).exists())) {
        System.err.println(resPath);
        return false;
      }
    }
    return true;
  }

  private static void pause() {
    try {
      Thread.sleep(15L * 1000L);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  private static void measureListOutdatedRelays(File tarballFile) {
    
  }

  private static void measureAverageAdvertisedBandwidth(
      File tarballFileOrDirectory) {
    System.out.println("Starting measureAverageAdvertisedBandwidth");
    long startedMillis = System.currentTimeMillis();
    long sumAdvertisedBandwidth = 0, countedServerDescriptors = 0;
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.addTarball(tarballFileOrDirectory);
    descriptorReader.addDirectory(tarballFileOrDirectory);
    Iterator<DescriptorFile> descriptorFiles =
        descriptorReader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor descriptor : descriptorFile.getDescriptors()) {
        if (!(descriptor instanceof ServerDescriptor)) {
          continue;
        }
        ServerDescriptor serverDescriptor = (ServerDescriptor) descriptor;
        sumAdvertisedBandwidth += (long) Math.min(Math.min(
            serverDescriptor.getBandwidthRate(),
            serverDescriptor.getBandwidthBurst()),
            serverDescriptor.getBandwidthObserved());
        countedServerDescriptors++;
      }
    }
    long endedMillis = System.currentTimeMillis();
    System.out.println("Ending measureAverageAdvertisedBandwidth");
    System.out.printf("Total time: %d millis%n",
        endedMillis - startedMillis);
    System.out.printf("Processed server descriptors: %d%n",
        countedServerDescriptors);
    System.out.printf("Average advertised bandwidth: %d%n",
        sumAdvertisedBandwidth / countedServerDescriptors);
    System.out.printf("Time per server descriptor: %.6f millis%n",
        ((double) (endedMillis - startedMillis))
        / ((double) countedServerDescriptors));
  }

  private static void measureFractionRelaysExit80ServerDescriptors(
      File tarballFile) {
    
  }

  private static void measureSumOfWrittenAndReadBytes(File tarballFile) {

  }

  private static void measureCountriesV3Requests(File tarballFile) {
    System.out.println("Starting measureCountriesV3Requests");
    long startedMillis = System.currentTimeMillis();
    Set<String> countries = new HashSet<>();
    long countedExtraInfoDescriptors = 0;
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.addTarball(tarballFile);
    Iterator<DescriptorFile> descriptorFiles =
        descriptorReader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor descriptor : descriptorFile.getDescriptors()) {
        if (!(descriptor instanceof ExtraInfoDescriptor)) {
          continue;
        }
        ExtraInfoDescriptor extraInfoDescriptor =
            (ExtraInfoDescriptor) descriptor;
        SortedMap<String, Integer> dirreqV3Reqs =
            extraInfoDescriptor.getDirreqV3Reqs();
        if (dirreqV3Reqs != null) {
          countries.addAll(dirreqV3Reqs.keySet());
        }
        countedExtraInfoDescriptors++;
      }
    }
    long endedMillis = System.currentTimeMillis();
    System.out.println("Ending measureCountriesV3Requests");
    System.out.printf("Total time: %d millis%n",
        endedMillis - startedMillis);
    System.out.printf("Processed extra-info descriptors: %d%n",
        countedExtraInfoDescriptors);
    System.out.printf("Number of countries: %d%n",
        countries.size());
    System.out.printf("Time per extra-info descriptor: %.6f millis%n",
        ((double) (endedMillis - startedMillis))
        / ((double) countedExtraInfoDescriptors));
  }

  private static void measureAverageRelaysExit(
      File tarballFileOrDirectory) {
    System.out.println("Starting measureAverageRelaysExit");
    long startedMillis = System.currentTimeMillis();
    long totalRelaysWithExitFlag = 0L, totalRelays = 0L,
        countedConsensuses = 0L;
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.addTarball(tarballFileOrDirectory);
    descriptorReader.addDirectory(tarballFileOrDirectory);
    Iterator<DescriptorFile> descriptorFiles =
        descriptorReader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor descriptor : descriptorFile.getDescriptors()) {
        if (!(descriptor instanceof RelayNetworkStatusConsensus)) {
          continue;
        }
        RelayNetworkStatusConsensus consensus =
            (RelayNetworkStatusConsensus) descriptor;
        for (NetworkStatusEntry entry :
            consensus.getStatusEntries().values()) {
          if (entry.getFlags().contains("Exit")) {
            totalRelaysWithExitFlag++;
          }
          totalRelays++;
        }
        countedConsensuses++;
      }
    }
    long endedMillis = System.currentTimeMillis();
    System.out.println("Ending measureAverageRelaysExit");
    System.out.printf("Total time: %d millis%n",
        endedMillis - startedMillis);
    System.out.printf("Processed consensuses: %d%n", countedConsensuses);
    System.out.printf("Total number of status entries: %d%n",
        totalRelays);
    System.out.printf("Total number of status entries with Exit flag: "
        + "%d%n", totalRelaysWithExitFlag);
    System.out.printf("Average number of relays with Exit Flag: %.2f%n",
        (double) totalRelaysWithExitFlag / (double) totalRelays);
    System.out.printf("Time per consensus: %.6f millis%n",
        ((double) (endedMillis - startedMillis))
        / ((double) countedConsensuses));
  }

  private static void measureVotesByBandwidthAuthorities(
      File tarballFile) {
    
  }

  private static void measureExtendedFamilies(File tarballFile) {
    
  }

  private static void measureFractionRelaysExit80Microdescriptors(
      File tarballFile) {
    System.out.println("Starting "
        + "measureFractionRelaysExit80Microdescriptors");
    long startedMillis = System.currentTimeMillis();
    long totalRelaysWithExitFlag = 0L, countedMicrodescriptors = 0L;
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.addTarball(tarballFile);
    Iterator<DescriptorFile> descriptorFiles =
        descriptorReader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor descriptor : descriptorFile.getDescriptors()) {
        if (!(descriptor instanceof Microdescriptor)) {
          continue;
        }
        countedMicrodescriptors++;
        Microdescriptor microdescriptor =
            (Microdescriptor) descriptor;
        String defaultPolicy = microdescriptor.getDefaultPolicy();
        if (defaultPolicy == null) {
          continue;
        }
        boolean accept = "accept".equals(
            microdescriptor.getDefaultPolicy());
        for (String ports : microdescriptor.getPortList().split(",")) {
          if (ports.contains("-")) {
            String[] parts = ports.split("-");
            int from = Integer.parseInt(parts[0]);
            int to = Integer.parseInt(parts[1]);
            if (from <= 80 && to >= 80) {
              if (accept) {
                totalRelaysWithExitFlag++;
              }
            } else if (to > 80) {
              if (!accept) {
                totalRelaysWithExitFlag++;
              }
              break;
            }
          } else if ("80".equals(ports)) {
            if (accept) {
              totalRelaysWithExitFlag++;
            }
            break;
          }
        }
      }
    }
    long endedMillis = System.currentTimeMillis();
    System.out.println("Ending "
        + "measureFractionRelaysExit80Microdescriptors");
    System.out.printf("Total time: %d millis%n",
        endedMillis - startedMillis);
    System.out.printf("Processed microdescriptors: %d%n",
        countedMicrodescriptors);
    System.out.printf("Total number of microdescriptors that exit to 80: "
        + "%d%n", totalRelaysWithExitFlag);
    System.out.printf("Average number of relays that exit to 80: %.2f%n",
        (double) totalRelaysWithExitFlag
        / (double) countedMicrodescriptors);
    System.out.printf("Time per microdescriptor: %.6f millis%n",
        ((double) (endedMillis - startedMillis))
        / ((double) countedMicrodescriptors));
  }
}

