#!/usr/bin/env bash

if [[ $# != 1 ]] ; then
    echo "Please specify the path to the gen directory to modify."
    echo "This script changes all the paths in the gen directory specified to the ones in the scion \
directory in the GOPATH (SC environment variable as in tutorials) so it can be used with the scion.sh script."
    echo "The tool will point the gen, gen-certs, gen-cache, bin, and logs to the local directory, \
i.e., assumes that the scion.sh script will run in the same directory as the gen directory."
    echo "Usage:    $0 path/to/gen"
    exit 0
fi


for f in $(find $1 -name "supervisord.conf" -o -name "*.toml"); do
    echo ${f}
    sed -i 's+/usr/bin/+bin/+g' ${f}
    sed -i 's+/var/log/scion/+logs/+g' ${f}
    sed -i 's+/var/lib/scion/+gen-cache/+g' ${f}
    sed -i 's+/etc/scion/gen-certs/+gen-certs/+g' ${f}
    sed -i 's+/etc/scion/gen/+gen/+g' ${f}
done

echo "DONE"