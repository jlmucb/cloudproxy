Read Me
=======


This documentation directory supports all versions of CloudProxy: Linux 
host only, KVM host, CloudProxy Hypervisor Host (future) and 
applications.

An overall description is in CloudProxyTechReport.pdf as well as
powerpoint slides in the not obviously named file Hypervisor.pptx.

To build fileProxy consisting of the the modified host Linux, the Tao 
providers including tcService, tpm and keyNegoServer.  Start at 
Overview.txt and follow the directions linearly.  Overview will refer
to subsidiary files which describe preparing the hardware (TPM) and
Linux as well as building the fileClient and fileServer reference
implementations as well as provisioning all the components including
the initram filesystem.

The KVM version has two components: the Linux host version (including
hardware preparation) described above plus instructions on building,
configuring and provisioning the KVM host and preparing the GuestOS
partitions.  The latter is described in kvm.txt and 
BuildandProvisionGuestOs.txt.  There is also some reference material
on KVM and VirtLib.

There is also additional documentation on the TPM, debugging Linux
and configuring grub although the documentation here is a "starter"
and is not intended to be authoritative, up-to-date or complete.

We welcome comments, suggestions, corrections and questions but
currently we are a very small group and will often not be able to
respond quickly to questions.

The instructions are written for executable program structure rooted
in /home/jlm/jlmcrypt.  To change this define the environment
variable CPProgramDirectory to point to the right place.

During operation, fileClient assumes keyNegoServer and fileServer are
at address 127.0.0.1.  To change this default, define the environment
variable CPKeyNegoAddress with the correct address for keyNegoServer
and CPFileServerAddress with the correct address of fileServer.

John (jlmucbmath@gmail.com) and Tom (tmroeder@google.com)
