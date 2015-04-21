#!/bin/sh
# $FreeBSD$

libkey() {
	libkey="lib_symbols_$1"
	patterns=[.+,-]
	replacement=_
	while :; do
		case " ${libkey} " in
			*${patterns}*)
				libkey="${libkey%%${patterns}*}${replacement}${libkey#*${patterns}}"
				;;
			*)
				break
				;;
		esac
	done
	return 0
}

ret=0
CHECK_UNRESOLVED=1
while getopts "U" flag; do
	case "${flag}" in
		U) CHECK_UNRESOLVED=0 ;;
	esac
done
shift $((OPTIND-1))

mime=$(file -L --mime-type $1)
isbin=0
case $mime in
*application/x-executable) isbin=1 ;;
*application/x-sharedlib);;
*) echo "Not an elf file" >&2 ; exit 1;;
esac

# Gather all symbols from the target
unresolved_symbols=$(nm -D --format=posix "$1" | awk -v isbin=${isbin} '$2 == "U" || ($2 == "B" && $4 != "" && isbin == 1) {print $1}' | tr '\n' ' ')
ldd_libs=$(ldd $(realpath $1) | awk '{print $1 ":" $3}')

# Check for useful libs
list_libs=
resolved_symbols=
for lib in $(readelf -d $1 | awk '$2 ~ /\(?NEEDED\)?/ { sub(/\[/,"",$NF); sub(/\]/,"",$NF); print $NF }'); do
	echo -n "checking if $lib is needed: "
	for libpair in ${ldd_libs}; do
		case "${libpair}" in
			${lib}:*) libpath="${libpair#*:}" && break ;;
		esac
	done
	list_libs="$list_libs $lib"
	foundone=
	lib_symbols="$(nm -D --defined-only --format=posix "${libpath}" | awk '$2 ~ /C|R|D|T|W|B|V/ {print $1}' | tr '\n' ' ')"
	if [ ${CHECK_UNRESOLVED} -eq 1 ]; then
		# Save the global symbols for this lib
		libkey "${lib}"
		setvar "${libkey}" "${lib_symbols}"
	fi
	for fct in ${lib_symbols}; do
		case " ${unresolved_symbols} " in
			*\ ${fct}\ *) foundone="${fct}" && break ;;
		esac
	done
	if [ -n "${foundone}" ]; then
		echo "yes... ${foundone}"
	else
		echo "no"
		ret=1
	fi
done

if [ ${CHECK_UNRESOLVED} -eq 1 ]; then
	# Add in crt1 symbols
	list_libs="${list_libs} crt1.o"
	lib_symbols="$(nm --defined-only --format=posix "/usr/lib/crt1.o" | awk '$2 ~ /C|R|D|T|W|B|V/ {print $1}' | tr '\n' ' ')"
	# Save the global symbols for this lib
	libkey "crt1.o"
	setvar "${libkey}" "${lib_symbols}"

	# No search libs for all symbols and report missing ones.
	for sym in ${unresolved_symbols}; do
		found=0
		for lib in ${list_libs}; do
			libkey "${lib}"
			eval "lib_symbols=\"\${${libkey}}\""
			# lib_symbols now contains symbols for the lib.
			case " ${lib_symbols} " in
				*\ ${sym}\ *) found=1 && break ;;
			esac
		done
		if [ $found -eq 0 ]; then
			echo "Unresolved symbol $sym"
			ret=1
		fi
	done
fi

exit ${ret}
