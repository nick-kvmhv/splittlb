//============================================================================
// Name        : TlbSplitMonitor.cpp
// Author      : nick-kvmhv
// Version     :
// Copyright   : MIT license
// Description : Monitor for split tlb pages being flipped by the application
//				 activity
//============================================================================

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <linux/types.h>
#include <unistd.h>
using namespace std;

struct kvm_ept_violation_tracker_entry {
	__u32 counter;
	__u16 read;
	__u16 vmnumber;
	__u64 gva;
	__u64 rip;
	__u64 cr3;
} __attribute__( ( packed ) ) ;

class ept_flip_record {
public:
	__u64 gva;
	__u64 rip;
	__u64 cr3;
	__u16 vmnumber;
	bool operator > (const ept_flip_record& snd) const {
		if (rip!=snd.rip)
			return rip>snd.rip;
		else if (cr3!=snd.cr3)
			return cr3>snd.cr3;
		else
			return vmnumber>snd.vmnumber;
	}
	bool operator < (const ept_flip_record& snd) const {
		if (rip!=snd.rip)
			return rip<snd.rip;
		else if (cr3!=snd.cr3)
			return cr3<snd.cr3;
		else
			return vmnumber<snd.vmnumber;
	}
};

const std::string DEBUGFS_NAME = "/sys/kernel/debug/kvm/tlb_split";

int main() {
	__u32 maxrecords;
	__u32 maxcounter = 0;
	set<ept_flip_record> flips;
	do {
		ifstream reader(DEBUGFS_NAME.c_str(), ios::binary | ios::in);
		cout << "\033[2J\033[1;1H";
		reader.read(reinterpret_cast<char *>(&maxrecords),sizeof maxrecords);

		if (!reader.good()) {
			cout << "Could not open " << DEBUGFS_NAME << " rdstate:" << reader.rdstate() << '\n';
			return 1;
		}

		cout << "Maxrecords:" << std::dec << maxrecords << std::hex<< '\n';
		map<__u32,kvm_ept_violation_tracker_entry> entries;
		for (__u32 i = 0; i < maxrecords; i++ ) {
			kvm_ept_violation_tracker_entry entry;
			reader.read(reinterpret_cast<char *>(&entry),sizeof entry);
			if (entry.counter>maxcounter)
				entries[entry.counter] = entry;
			//cout << "counter:" << entry.counter << " vm:" << entry.vmnumber << " Read:" << entry.read << std::hex << " gva:" << entry.gva << " rip:" << entry.rip << " cr3:" << entry.cr3 << '\n';
		}
		for (auto it = entries.begin();it!=entries.end();it++) {
			if (it->second.counter > maxcounter) {
				if ((it->second.counter - maxcounter) > 1)
					cout << "Skipped some records " << it->second.counter << " from " << maxcounter << '\n';
				maxcounter = it->second.counter;
				cout << "counter:" << it->second.counter << " vm:" << it->second.vmnumber << " Read:" << it->second.read << std::hex << " gva:" << it->second.gva << " rip:" << it->second.rip << " cr3:" << it->second.cr3 << '\n';
				if (it->second.read) {
					const ept_flip_record flip = {.gva = it->second.gva,.rip = it->second.rip,.cr3 = it->second.cr3,.vmnumber = it->second.vmnumber};
					if (flips.find(flip)==flips.end())
						flips.insert(flip);
				}
			}
		}
		if (!flips.empty())
			cout << "*********************************************************************************************************\n";
		for (auto it = flips.begin(); it!=flips.end(); it++) {
			cout << "Flip vm:" << it->vmnumber << " rip:" << it->rip << " gva:" << it->gva << " cr3:" << it->cr3 << '\n';
		}
		sleep(3);
	} while (true);
	return 0;
}
