#!/bin/sh

set -e

for driver in 1 2; do
    rm -f /tmp/kubench
    for xform in encrypt decrypt; do
        for mode in aes-gcm-128 aes-gcm-192 aes-gcm-256; do
            for psize in 1 15 16 17 47 48 49 63 64 65 384 512 1023 1024 1025 1400 4096; do
                for asize in 0 1 15 16 17 47 48 49 63 64 65 384 512 1023 1024 1025 1400 4096; do
                    cmd=$(printf "cipher=%s;payload_length=%s;op=%s;max_inflight=1;count=100000;aad_length=%s;driver=%s" \
                        "${mode}" "${psize}" "${xform}" "${asize}" "${driver}")
                    echo "$cmd" | tee -a /tmp/kubench
                    sysctl debug.kubench.opencrypto.run="$cmd"
                done
            done
        done
    done

    if [ $driver -eq 1 ]; then
        cp -f /tmp/kubench /tmp/kubench-aesni
    else
        cp -f /tmp/kubench /tmp/kubench-ossl
    fi
done

for driver in aesni ossl; do
    rm -f /tmp/kubench-${driver}-avgs
    awk '/^kubench:/{print $NF} /^cipher=/{print}' /tmp/kubench-$driver > /tmp/kubench-${driver}-avgs
done

rm -f /tmp/kubench-comb
paste /tmp/kubench-aesni-avgs /tmp/kubench-ossl-avgs | sed 's/^\(cipher=.*\);driver=1.*/\1/' > /tmp/kubench-comb
