#include <iostream>
#include <pcap.h>
#include <map>
#include <vector>
#include <ctime>
#include <cstring>
#include <fstream>
#include <cstdlib> 

struct PacketStats {
    int packet_count = 0;  
    int total_size = 0;    
    
    void addPacket(int size) {
        packet_count++;
        total_size += size;
    }
    
    double averagePacketSize() const {
        return packet_count == 0 ? 0 : static_cast<double>(total_size) / packet_count;
    }
};

void analyze_pcap(const char *filename, int quantum) {
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle = pcap_open_offline(filename, errbuf);  
    
    if (!handle) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return;
    }
    
    struct pcap_pkthdr *header;  
    const u_char *data;          
    std::map<time_t, PacketStats> stats;  
    
    while (pcap_next_ex(handle, &header, &data) == 1) {
        // Align timestamp to the quantum interval
        time_t timestamp = header->ts.tv_sec - (header->ts.tv_sec % quantum);
        stats[timestamp].addPacket(header->caplen);  
    }
    
    pcap_close(handle);  // Close the PCAP file
    
    std::ofstream output("packet_stats.csv");
    output << "Time,Packet Count,Total Volume,Average Packet Size\n";
    
    for (const auto &entry : stats) {
        output << entry.first << "," 
               << entry.second.packet_count << "," 
               << entry.second.total_size << "," 
               << entry.second.averagePacketSize() << "\n";
    }
    
    output.close();
    std::cout << "Analysis complete. Data written to packet_stats.csv" << std::endl;
    
    std::ofstream gnuplot_script("plot_packets.gnu");
    gnuplot_script << "set terminal png\n";
    gnuplot_script << "set output 'packet_stats.png'\n";
    gnuplot_script << "set title 'Packet Statistics'\n";
    gnuplot_script << "set xlabel 'Time (seconds)'\n";
    gnuplot_script << "set ylabel 'Packet Count'\n";
    gnuplot_script << "set grid\n";
    gnuplot_script << "plot 'packet_stats.csv' using 1:2 with lines title 'Packet Count'\n";
    gnuplot_script.close();
    
    system("gnuplot plot_packets.gnu");
    std::cout << "Plot generated as packet_stats.png" << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> [quantum]" << std::endl;
        return 1;
    }

    int quantum = (argc > 2) ? std::stoi(argv[2]) : 1;

    analyze_pcap(argv[1], quantum);
    return 0;
}