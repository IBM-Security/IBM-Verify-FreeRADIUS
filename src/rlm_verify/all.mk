#######################################################################
#
# TARGET should be set by autoconf only.  Don't touch it.
#
# The SOURCES definition should list ALL source files.
#
# SRC_CFLAGS defines addition C compiler flags.  You usually don't
# want to modify this, though.  Get it from autoconf.
#
# The TGT_LDLIBS definition should list ALL required libraries.
#
#######################################################################

TARGETNAME	:= rlm_verify

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c sdk/isam.c sdk/cJSON.c 

SRC_CFLAGS	:=  -g
TGT_LDLIBS	:=  -lc -lcurl -lpthread

#
#  If the target has documentation in man format it should be set here
#
#MAN		:= example.8

#
#  Install targets are automagically created for libraries and binary targets,
#  you only need to create manual targets for things like example scripts, and
#  support files.
#
#  The installation directory target should always be listed first, and should
#  be one of:
#	* install.raddbdir
#	* install.bindir
#	* install.sbindir

#install: install.raddbdir $(R)$(raddbdir)/example.sh

#$(R)$(raddbdir)/example.pl: src/modules/$(TARGETNAME)/example.sh
#	@$(INSTALL) -m 755 src/modules/$(TARGETNAME)/example.sh $(R)$(raddbdir)/
