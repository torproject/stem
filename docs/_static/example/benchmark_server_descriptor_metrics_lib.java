package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;
import org.torproject.descriptor.DescriptorSourceFactory;

public class MeasurePerformance {
  public static void main(String[] args) {
    measureAverageAdvertisedBandwidth(new File("server-descriptors-2015-11.tar"));
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
}
