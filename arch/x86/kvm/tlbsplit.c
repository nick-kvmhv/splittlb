/*
 * tlbsplit.c
 *
 *  Created on: Dec 28, 2015
 *      Author: nick
 */

#include "tlbsplit.h"
#include <asm/vmx.h>
#include <linux/debugfs.h>
//#include <linux/gfp.h>
#include "mmu.h"

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))

#define PTE_WRITE (1<<1)
#define PTE_READ (1<<0)
#define PTE_EXECUTE (1<<2)

#define KVM_MAX_TRACKER 100

struct kvm_ept_violation_tracker_entry {
	u32 counter;
	u16 read;
	u16 vmnumber;
	u64 gva;
	u64 rip;
	u64 cr3;
} __attribute__( ( packed ) ) ;

atomic_t split_tracker_next_write;
struct kvm_ept_violation_tracker {
	int max_number_of_entries;
	struct kvm_ept_violation_tracker_entry entries[KVM_MAX_TRACKER];
} __attribute__( ( packed ) ) split_tracker;

static struct dentry *split_dentry;

static int next_vm;

/* read file operation */
static ssize_t split_counter_reader(struct file *fp, char __user *user_buffer,
                                size_t count, loff_t *position)
{
     return simple_read_from_buffer(user_buffer, count, position, &split_tracker, sizeof split_tracker);
}

static const struct file_operations split_debug = {
        .read = split_counter_reader,
};

void split_init_debugfs(void) {
	atomic_set(&split_tracker_next_write,0);
	split_tracker.max_number_of_entries = KVM_MAX_TRACKER;
	split_dentry = debugfs_create_file("tlb_split", 0444, kvm_debugfs_dir, NULL, &split_debug);
	printk(KERN_INFO "tlb_split_init:debugfs_create_file returned 0%lx\n",(unsigned long)split_dentry);
	next_vm = 0;
}

void _register_ept_flip(gva_t gva,gva_t rip,unsigned long cr3,int vmnumber,bool read) {
	int counter = atomic_inc_return(&split_tracker_next_write);
	int nextRow = (counter - 1) % KVM_MAX_TRACKER;
	split_tracker.entries[nextRow].gva = gva;
	split_tracker.entries[nextRow].rip = rip;
	split_tracker.entries[nextRow].cr3 = cr3;
	split_tracker.entries[nextRow].vmnumber = vmnumber;
	split_tracker.entries[nextRow].read = read;
	split_tracker.entries[nextRow].counter = counter;
}

void split_shutdown_debugfs(void) {
	debugfs_remove(split_dentry);
}

bool tlb_split_init(struct kvm *kvm) {
	kvm->splitpages = kzalloc(sizeof(struct kvm_splitpages), GFP_KERNEL);
	if (kvm->splitpages!=NULL) {
		kvm->splitpages->vmcounter = next_vm++;
		return true;
	}
	else
		return false;
}

void kvm_split_tlb_freepage(struct kvm_splitpage *page)
{
	page->cr3 = 0;
	page->gpa = 0;
	page->active = 0;
	page->gva = 0;
	page->codeaddr = 0;
	if (page->dataaddr) {
		kfree(page->dataaddr);
		page->dataaddr = NULL;
	}
}
EXPORT_SYMBOL_GPL(kvm_split_tlb_freepage);

void kvm_split_tlb_deactivateall(struct kvm *kvm) {
	struct kvm_splitpages *spages = kvm->splitpages;
	int i;
	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++)
		kvm_split_tlb_freepage(&spages->pages[i]);
	kfree(kvm->splitpages);
}
EXPORT_SYMBOL_GPL(kvm_split_tlb_deactivateall);

static struct kvm_splitpage* _split_tlb_findpage(struct kvm *kvms,gpa_t gpa) {
	int i;
	struct kvm_splitpage* found;
	gpa_t pagestart;
	pagestart = gpa&PAGE_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->gpa == pagestart)
			return found;
	}
	return NULL;
}

struct kvm_splitpage* split_tlb_findpage(struct kvm *kvms,gpa_t gpa) {
	if (gpa&PAGE_MASK)
		return _split_tlb_findpage(kvms,gpa);
	else
		return NULL;
}
EXPORT_SYMBOL_GPL(split_tlb_findpage);

struct kvm_splitpage* split_tlb_findpage_gva_cr3(struct kvm *kvms, gva_t gva, ulong cr3) {
	struct kvm_splitpage* found;
	gva_t pagestart;
	int i;
	pagestart = gva&PAGE_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->gva == pagestart && found->cr3 == cr3)
			return found;
	}
	return NULL;
}


int split_tlb_setdatapage(struct kvm_vcpu *vcpu, gva_t gva, gva_t datagva, ulong cr3) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	gpa_t translated;
	int r;
	access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split:tlb_setdatapage gva:0x%lx gpa not found %d\n",gva,exception.error_code);
		gpa = 0;
	}
	printk(KERN_WARNING "split:tlb_setdatapage cr3:0x%lx gva:0x%lx gpa:0x%llx\n",cr3,gva,gpa);
	if (gpa!=0)
		page = split_tlb_findpage(vcpu->kvm,gpa);
	else
		page = split_tlb_findpage_gva_cr3(vcpu->kvm,gva,cr3);
	if (page == NULL) {
		page = _split_tlb_findpage(vcpu->kvm,0);
		if (page == NULL) {
			printk(KERN_WARNING "No more slots in the split page table\n");
			return 0;
		}
		page->cr3 = cr3;
		page->gpa = gpa&PAGE_MASK;
		page->gva = gva&PAGE_MASK;
		page->dataaddr = kmalloc(4096,GFP_KERNEL);
		BUG_ON(((long unsigned int)page->dataaddr&~PAGE_MASK)!=0);
		translated = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, datagva&PAGE_MASK, access, &exception);
		if (translated == UNMAPPED_GVA) {
			printk(KERN_WARNING "split:tlb_setdatapage gva:0x%lx gpa not found for data %d\n",datagva,exception.error_code);
			return 0;
		}
		r = kvm_read_guest(vcpu->kvm,translated,page->dataaddr,4096);
		printk(KERN_WARNING "split:tlb_setdatapage cr3:0x%lx gva:0x%lx gpa:0x%llx allocated:0x%llx copy result:%d\n",cr3,gva,gpa,(u64)page->dataaddr,r);
	} else {
		printk(KERN_WARNING "Already a page for: gpa:0x%llx with cr3:0x%lx and gva=0x%lx\n",gpa,page->cr3,page->gva);
		return 0;
	}
	return 1;
}
//EXPORT_SYMBOL_GPL(split_tlb_setdatapage);


int split_tlb_activatepage(struct kvm_vcpu *vcpu, gva_t gva, ulong cr3) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	u64* sptep;
	//struct kvm_shadow_walk_iterator iterator;
	gfn_t gfn;

	access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split:split_tlb_activatepage gva:0x%lx gpa not found %d\n",gva,exception.error_code);
		return 0;
	}
	page = split_tlb_findpage_gva_cr3(vcpu->kvm,gva,cr3);
	if (page == NULL) {
		printk(KERN_WARNING "split:tlb_activatepage page not foundcr3:0x%lx gva:0x%lx translated gpa:0x%llx \n",cr3,gva,gpa);
		return 0;
	}
	printk(KERN_WARNING "split:tlb_activatepage found page cr3:0x%lx gva:0x%lx gpa:0x%llx page_gpa:0x%llx\n",cr3,gva,gpa,page->gpa);
	if (page->gpa != (gpa&PAGE_MASK) ) {
		printk(KERN_WARNING "split:tlb_activatepage gpa changed 0x%llx->0x%llx, adjusting\n",page->gpa,gpa&PAGE_MASK);
		page->gpa = gpa&PAGE_MASK;
	}

	gfn = gpa >> PAGE_SHIFT;
	sptep = split_tlb_findspte(vcpu,gfn);
	if (sptep!=NULL) {
		u64 newspte = *sptep & ~(VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK);
		//newspte = 0L;
		printk(KERN_WARNING "split_tlb_activatepage: spte=0x%llx->newspte=0x%llx\n",*sptep,newspte);
        *sptep = newspte;
        page->active = true;
		kvm_flush_remote_tlbs(vcpu->kvm);
		return 1;
	} else
		printk(KERN_WARNING "split_tlb_activatepage: spte not found 0x%llx\n",gpa);
	return 0;
}
//EXPORT_SYMBOL_GPL(split_tlb_activatepage);

int split_tlb_restore_spte_atomic(struct kvm *kvms,gfn_t gfn,u64* sptep,hpa_t stepaddr) {
	if (sptep!=NULL) {
		u64 newspte = *sptep;
		if ((newspte&VMX_EPT_READABLE_MASK)==0||(newspte&VMX_EPT_EXECUTABLE_MASK)==0||(newspte&VMX_EPT_WRITABLE_MASK)==0) {
			newspte|=VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=(stepaddr<<PAGE_SHIFT)&PT64_BASE_ADDR_MASK;
			printk(KERN_WARNING "split_tlb_restore_spte_atomic: fixing spte 0%llx->0%llx for 0%llx\n", *sptep, newspte, gfn<<PAGE_SHIFT);
			*sptep = newspte;
		} else
			printk(KERN_WARNING "split_tlb_restore_spte_atomic: spte for 0%llx seems untouched: 0%llx\n", gfn<<PAGE_SHIFT, *sptep);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_restore_spte_atomic: spte not found for 0x%llx\n", gfn<<PAGE_SHIFT);
		return 0;
	}
}

int split_tlb_restore_spte(struct kvm_vcpu *vcpu,gfn_t gfn) {
	bool async,writable;
	int result;
	u64* sptep;
	hpa_t stepaddr = gfn_to_pfn_async(vcpu->kvm,gfn,&async,false,&writable);
	if (async || !writable)
		printk(KERN_WARNING "split_tlb_restore_spte: unexpected async:%d writable%d gpa:0%llx hfn:0%llx\n", async, writable, gfn<<PAGE_SHIFT,stepaddr);
	spin_lock(&vcpu->kvm->mmu_lock);
	sptep = split_tlb_findspte(vcpu,gfn);
	if (sptep!=NULL && *sptep==0) {
		spin_unlock(&vcpu->kvm->mmu_lock);
		printk(KERN_WARNING "split_tlb_restore_spte: zero spte, falling back to default handler gpa:0%llx\n", gfn<<PAGE_SHIFT);
		return 0;
	}
	result = split_tlb_restore_spte_atomic(vcpu->kvm,gfn,sptep,stepaddr);
	spin_unlock(&vcpu->kvm->mmu_lock);
	return result;
}

int split_tlb_restore_spte_base(struct kvm *kvms,gfn_t gfn,u64* sptep) {
	bool async,writable;
	hpa_t stepaddr = gfn_to_pfn_async(kvms,gfn,&async,false,&writable);
	if (async || !writable)
		printk(KERN_WARNING "split_tlb_restore_spte_base: unexpected async:%d writable%d gpa:0%llx\n", async, writable, gfn<<PAGE_SHIFT);
	return split_tlb_restore_spte_atomic(kvms,gfn,sptep,stepaddr);
}

int split_tlb_flip_to_code(struct kvm *kvms,hpa_t hpa,u64* sptep) {
	if (sptep!=NULL) {
		u64 newspte = *sptep;
		if ((newspte&VMX_EPT_READABLE_MASK)!=0||(newspte&VMX_EPT_EXECUTABLE_MASK)==0||(newspte&VMX_EPT_WRITABLE_MASK)==0) {
			WARN_ON(hpa==0);
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_READABLE_MASK);
			newspte|=VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=hpa&PT64_BASE_ADDR_MASK;
			printk(KERN_WARNING "split_tlb_flip_to_code: fixing spte 0%llx->0%llx for 0%llx\n", *sptep, newspte, hpa);
			*sptep = newspte;
		} else
			printk(KERN_WARNING "split_tlb_flip_to_code: spte for 0%llx seems untouched: 0%llx\n", hpa, *sptep);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_flip_to_code: spte not found for hpa 0x%llx\n", hpa);
		return 0;
	}
}


int split_tlb_freepage(struct kvm_vcpu *vcpu, gva_t gva) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	gfn_t gfn;

	access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split:tlb_freepage gva:0x%lx gpa not found %d\n",gva,exception.error_code);
		return 0;
	}

	gfn = gpa >> PAGE_SHIFT;
	page = split_tlb_findpage(vcpu->kvm,gpa);
	if (page!=NULL) {
		if (page->active) {
			int rc = kvm_write_guest(vcpu->kvm,gpa&PAGE_MASK,page->dataaddr,4096);
			split_tlb_restore_spte(vcpu,gfn);
			printk(KERN_WARNING "split:tlb_freepage copying data cr3:0x%lx gva:0x%lx gpa:0x%llx cpyrc:%d\n",page->cr3,page->gva,page->gpa,rc);
		} else {
			printk(KERN_WARNING "split:tlb_freepage inactive page cr3:0x%lx gva:0x%lx gpa:0x%llx\n",page->cr3,page->gva,page->gpa);
		}
		kvm_split_tlb_freepage(page);
		return 1;
	} else
		printk(KERN_WARNING "split:tlb_freepage page not found gpa:0x%llx\n",gpa);
	return 0;
}
//EXPORT_SYMBOL_GPL(split_tlb_freepage);

int split_tlb_flip_page(struct kvm_vcpu *vcpu, gpa_t gpa, struct kvm_splitpage* splitpage, unsigned long exit_qualification)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long cr3 = kvm_read_cr3(vcpu);
	bool async,writable;
	phys_addr_t detouraddr = virt_to_phys(splitpage->dataaddr);


	if (exit_qualification & PTE_WRITE) //write
	{
		int rc;
		//newspte|=VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK;
		//newspte&=~PT64_BASE_ADDR_MASK;
		//newspte|=(stepaddr<<PAGE_SHIFT)&PT64_BASE_ADDR_MASK;
		printk(KERN_WARNING "split_tlb_flip_page: WRITE EPT fault at 0x%llx. detourpa:0x%llx rip:0x%lx\n vcpuid:%d Removing the page\n",gpa,detouraddr,rip,vcpu->vcpu_id);
		if (split_tlb_restore_spte(vcpu,gfn)==0)
			return 0;
		rc = kvm_write_guest(vcpu->kvm,gpa&PAGE_MASK,splitpage->dataaddr,4096);
		printk(KERN_WARNING "split_tlb_flip_page: WRITE EPT fault at 0x%llx data copied rc:%d\n",gpa,rc);
	} else if (exit_qualification & PTE_READ) //read
	{
		u64* sptep;
		hpa_t stepaddr = gfn_to_pfn_async(vcpu->kvm,gfn,&async,false,&writable);
		if (async || !writable)
			printk(KERN_WARNING "split_tlb_flip_page: unexpected async:%d writable%d\n", async, writable);
		spin_lock(&vcpu->kvm->mmu_lock);
		sptep = split_tlb_findspte(vcpu,gfn);
		if (exit_qualification & PTE_EXECUTE) //TODO handle execute&read, not sure if needed
			{
				printk(KERN_ERR "split_tlb_flip_page: read&execute EPT fault at 0x%llx. Need to handle it properly \n",gpa);
			}
		if (sptep!=NULL) {
			u64 newspte = *sptep;
			if (newspte==0) {
				printk(KERN_INFO "split_tlb_flip_page: fallback to default handler(READ):0x%llx \n",gpa);
				spin_unlock(&vcpu->kvm->mmu_lock);
				return 0;
			}
			if ((newspte&(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK|VMX_EPT_READABLE_MASK))==0) {
				printk(KERN_INFO "split_tlb_flip_page: sptep last 3 bits are 0 for gpa:0x%llx \n",gpa);
			}
			splitpage->codeaddr = stepaddr<<PAGE_SHIFT;
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK);
			newspte|=VMX_EPT_READABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=detouraddr&PT64_BASE_ADDR_MASK;
			//printk(KERN_WARNING "split_tlb_flip_page: read EPT fault at 0x%llx/0x%llx -> 0x%llx detourpa:0x%llx rip:0x%lx\n vcpuid:%d\n",gpa,*sptep,newspte,detouraddr,rip,vcpu->vcpu_id);
			*sptep = newspte;
		} else
			printk(KERN_ERR "split_tlb_flip_page: sptep not found for 0x%llx \n",gpa);
		spin_unlock(&vcpu->kvm->mmu_lock);
		_register_ept_flip(splitpage->gva,rip,cr3,vcpu->kvm->splitpages->vmcounter,true);
	} else if (exit_qualification & PTE_EXECUTE) //execute
	{
		u64* sptep;
		hpa_t stepaddr = gfn_to_pfn_async(vcpu->kvm,gfn,&async,false,&writable);
		if (async || !writable)
			printk(KERN_WARNING "split_tlb_flip_page: unexpected async:%d writable%d\n", async, writable);
		spin_lock(&vcpu->kvm->mmu_lock);
		sptep = split_tlb_findspte(vcpu,gfn);
		if (sptep!=NULL) {
			u64 newspte = *sptep;
			if (newspte==0) {
				printk(KERN_INFO "split_tlb_flip_page: fallback to default handler (EXEC):0x%llx \n",gpa);
				spin_unlock(&vcpu->kvm->mmu_lock);
				return 0;
			}
			if ((newspte&(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK|VMX_EPT_READABLE_MASK))==0) {
				printk(KERN_INFO "split_tlb_flip_page: sptep last 3 bits are 0 for gpa:0x%llx \n",gpa);
			}
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_READABLE_MASK);
			newspte|=VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=(stepaddr<<PAGE_SHIFT)&PT64_BASE_ADDR_MASK;
			//printk(KERN_WARNING "split_tlb_flip_page: execute EPT fault at 0x%llx/0x%llx -> 0x%llx detourpa:0x%llx rip:0x%lx\n vcpuid:%d\n",gpa,*sptep,newspte,detouraddr,rip,vcpu->vcpu_id);
			*sptep = newspte;
		} else
			printk(KERN_ERR "split_tlb_flip_page: sptep not found for 0x%llx \n",gpa);
		spin_unlock(&vcpu->kvm->mmu_lock);
		_register_ept_flip(splitpage->gva,rip,cr3,vcpu->kvm->splitpages->vmcounter,false);
	} else
		printk(KERN_ERR "split_tlb_flip_page: unexpected EPT fault at 0x%llx \n",gpa);
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_flip_page);

int deactivateAllPages(struct kvm_vcpu *vcpu) {
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	int i;
	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
		gva_t gva = spages->pages[i].gva;
		if (gva) {
			if (split_tlb_freepage(vcpu,spages->pages[i].gva)==0) {
				printk(KERN_WARNING "deactivateAllPages: split_tlb_freepage failed for gva=%lx attempting to fix and free it based on saved gpa\n",gva);
				split_tlb_restore_spte(vcpu,spages->pages[i].gpa >> PAGE_SHIFT);
				kvm_split_tlb_freepage(spages->pages+i);
			}
		}
	}
	return 1;
}

/*
 * rax low word - opcode, upper 3 words will be used for secret code
 *
 * 0x0001: Set data for page.
 * 		rbx - guest virtual address for page
 * 		rdx - guest virtual address for page data
 *
 * 0x0002: Activate page.
 * 		rbx - guest virtual address for page
 *
 * 0x0003: Set code for page. Only usable after page is active
 * 		rbx - guest virtual address for page
 * 		rdx - guest virtual address for page code
 *
 * 0x0004: Deactivate page.
 * 		rbx - guest virtual address for page
 *
 * 0x0005: check if support is present
 *
 * 0x0005: deactivate all
 *
 * 		return ax = 1 - success
 * 		ax = 0 - failure
 *
 */

int split_tlb_vmcall_dispatch(struct kvm_vcpu *vcpu)
{
	unsigned long rip,cr3,rax,rbx,rdx,rcx;
	int result;

	rip = kvm_rip_read(vcpu);
	cr3 = kvm_read_cr3(vcpu);
	rax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	rbx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	rdx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	printk(KERN_DEBUG "VMCALL: rip:0x%lx cr3:0x%lx rax:0x%lx rbx:0x%lx rcx:0x%lx rdx:0x%lx \n",rip,cr3,rax,rbx,rcx,rdx);

	switch (rax&0xFFFF) {
		case 0x0001:
			result = split_tlb_setdatapage(vcpu,rbx,rdx,cr3);
			break;
		case 0x0002:
			result = split_tlb_activatepage(vcpu,rbx,cr3);
		    break;
		case 0x0003:
			printk(KERN_WARNING "VMCALL: not implemented operation 0x%x \n",(unsigned short)(rax&0xFFFF));
			result = 0;
			break;
		case 0x0004:
			result = split_tlb_freepage(vcpu,rbx);
			break;
		case 0x0005:
			result = 1;
			break;
		case 0x0006:
			result = deactivateAllPages(vcpu);
			break;
		default:
			result = 0;
			printk(KERN_WARNING "VMCALL: invalid operation 0x%x \n",(unsigned short)(rax&0xFFFF));
	}
	kvm_register_write(vcpu, VCPU_REGS_RAX, result);
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_vmcall_dispatch);

int split_tlb_has_split_page(struct kvm *kvms, u64* sptep) {
	struct kvm_splitpage* found;
	int i;
	phys_addr_t pagehpa = *sptep & PT64_BASE_ADDR_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->active) {
			phys_addr_t detouraddr = virt_to_phys(found->dataaddr);
			printk(KERN_WARNING "split_tlb_has_split_page: comparing pagehpa:0x%llx with detouraddr:0x%llx\n",pagehpa,detouraddr);
			if (pagehpa == detouraddr) {
				printk(KERN_WARNING "split_tlb_has_split_page: found page gva:0x%lx reverting to code\n",found->gva);
				split_tlb_flip_to_code(kvms,found->codeaddr,sptep);
				return 1;
			}
		}
	}
	printk(KERN_WARNING "split_tlb_has_split_page: did not find split page spte:0x%llx\n",*sptep);
	return 0;
}

int split_tlb_handle_ept_violation(struct kvm_vcpu *vcpu,gpa_t gpa,unsigned long exit_qualification,int* splitresult) {
	struct kvm_splitpage* splitpage;

	splitpage = split_tlb_findpage(vcpu->kvm,gpa);
	if (splitpage!=NULL) {
		//printk(KERN_DEBUG "handle_ept_violation on split page: 0x%llx exitqualification:%lx\n",gpa,exit_qualification);
		if (split_tlb_flip_page(vcpu,gpa,splitpage,exit_qualification)){
			int emulation_type = EMULTYPE_RETRY;
			enum emulation_result er;
			er = x86_emulate_instruction(vcpu, gpa, emulation_type,  NULL, 0);
			if (er==EMULATE_DONE) {
				//printk(KERN_DEBUG "handle_ept_violation on split page after emulation EMULATE_DONE\n");
				*splitresult = 1;
			} else {
				printk(KERN_WARNING "handle_ept_violation on split page after emulation %s\n",er==EMULATE_FAIL?"EMULATE_FAIL":"EMULATE_USER_EXIT or smth");
				*splitresult = 0;
			}
		} else {
			printk(KERN_WARNING "handle_ept_violation split_tlb_flip_page returned 0 page: 0x%llx",gpa);
			return 0;
		}
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(split_tlb_handle_ept_violation);
