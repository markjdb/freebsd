#!/bin/sh
#
# $FreeBSD$
#

set -e

export ASSUME_ALWAYS_YES="YES"
export PKG_DBDIR="/tmp/pkg"
export PERMISSIVE="YES"
export REPO_AUTOUPDATE="NO"
export PKGCMD="/usr/sbin/pkg -d"

DVD_PACKAGES="archivers/unzip
devel/subversion
devel/subversion-static
emulators/linux_base-f10
misc/freebsd-doc-all
net/mpd5
net/rsync
ports-mgmt/pkg
ports-mgmt/portmaster
shells/bash
shells/zsh
security/sudo
sysutils/screen
www/firefox
www/links
x11-drivers/xf86-video-vmware
x11/gnome2
x11/kde4
x11/xorg"

# If NOPORTS is set for the release, do not attempt to build pkg(8).
if [ ! -f /usr/ports/Makefile ]; then
	echo "*** /usr/ports is missing!    ***"
	echo "*** Skipping pkg-stage.sh     ***"
	echo "*** Unset NOPORTS to fix this ***"
	exit 0
fi

if [ ! -x /usr/local/sbin/pkg ]; then
	/etc/rc.d/ldconfig restart
	/usr/bin/make -C /usr/ports/ports-mgmt/pkg install clean
fi

export DVD_DIR="dvd/packages"
export PKG_ABI=$(pkg config ABI)
export PKG_ALTABI=$(pkg config ALTABI 2>/dev/null)
export PKG_REPODIR="${DVD_DIR}/${PKG_ABI}"

/bin/mkdir -p ${PKG_REPODIR}
if [ ! -z "${PKG_ALTABI}" ]; then
	(cd ${DVD_DIR} && ln -s ${PKG_ABI} ${PKG_ALTABI})
fi

# Print pkg(8) information to make debugging easier.
${PKGCMD} -vv
${PKGCMD} update -f
${PKGCMD} fetch -o ${PKG_REPODIR} -d ${DVD_PACKAGES}

# Create the 'Latest/pkg.txz' symlink so 'pkg bootstrap' works
# using the on-disc packages.
mkdir -p ${PKG_REPODIR}/Latest
(cd ${PKG_REPODIR}/Latest && \
	ln -s ../All/$(${PKGCMD} rquery %n-%v pkg).txz pkg.txz)

${PKGCMD} repo ${PKG_REPODIR}

# Always exit '0', even if pkg(8) complains about conflicts.
exit 0
