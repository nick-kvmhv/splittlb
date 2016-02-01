/*
 * tlbsplit.h
 *
 *  Created on: Dec 28, 2015
 *      Author: nick
 */

#ifndef ARCH_X86_KVM_TLBSPLIT_H_
#define ARCH_X86_KVM_TLBSPLIT_H_
#include <linux/types.h>
#include <linux/export.h>
#include <linux/kvm_host.h>

#define KVM_MAX_SPLIT_PAGES 100

struct kvm_splitpage {
		gpa_t gpa;
		gva_t gva;
		unsigned long cr3;
		void * dataaddr;
		hpa_t codeaddr;
		bool active;
};

struct kvm_splitpages {
	struct kvm_splitpage pages[KVM_MAX_SPLIT_PAGES];
	int vmcounter;
};

bool tlb_split_init(struct kvm *kvm);
void kvm_split_tlb_freepage(struct kvm_splitpage *page);
void kvm_split_tlb_deactivateall(struct kvm *kvm);
void split_init_debugfs(void);
void split_shutdown_debugfs(void);

struct kvm_splitpage* split_tlb_findpage(struct kvm *kvms,gpa_t gpa);
int split_tlb_activatepage(struct kvm_vcpu *vcpu, gva_t gva, ulong cr3);
int split_tlb_setdatapage(struct kvm_vcpu *vcpu, gva_t gva, gva_t datagva, ulong cr3);
int split_tlb_flip_page(struct kvm_vcpu *vcpu, gpa_t gpa, struct kvm_splitpage* splitpage, unsigned long exit_qualification);
int split_tlb_freepage(struct kvm_vcpu *vcpu, gva_t gva);
int split_tlb_vmcall_dispatch(struct kvm_vcpu *vcpu);
int split_tlb_handle_ept_violation(struct kvm_vcpu *vcpu,gpa_t gpa,unsigned long exit_qualification,int* splitresult);
int split_tlb_has_split_page(struct kvm *kvms, u64* sptep);
int split_tlb_restore_spte(struct kvm_vcpu *vcpu,gfn_t gfn);
int split_tlb_restore_spte_base(struct kvm *kvms,gfn_t gfn,u64* sptep);
int split_tlb_flip_to_code(struct kvm *kvms,hpa_t hpa,u64* sptep);

#define COULD_BE_SPLIT_PAGE(spte) ( (spte&VMX_EPT_WRITABLE_MASK)==0 && (spte&(VMX_EPT_READABLE_MASK|VMX_EPT_EXECUTABLE_MASK))!=0 \
&& ( spte&(VMX_EPT_READABLE_MASK|VMX_EPT_EXECUTABLE_MASK))!=(VMX_EPT_READABLE_MASK|VMX_EPT_EXECUTABLE_MASK) )

#endif /* ARCH_X86_KVM_TLBSPLIT_H_ */
