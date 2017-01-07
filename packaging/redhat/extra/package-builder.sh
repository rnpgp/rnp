# This is a project-specific variant of a script written by Frank Trampe.
# It is hereby released under the license of the enclosing project.
# Call this with the desired version number as the first argument.
PNAME=netpgp;
PVERSION="$1";
# Make a new copy of the sources and name by version, clearing any remnant from before.
if [ -e "$PNAME"-"$PVERSION" ]; then rm -rf "$PNAME"-"$PVERSION"; fi;
cp -pRP "$PNAME" "$PNAME"-"$PVERSION";
# Clean the new sources.
(cd "$PNAME"-"$PVERSION"; if [ -e .git ]; then git clean -fdx; git reset --hard; fi;)
# Make the source tarball for the build.
tar -cjf "$PNAME"-"$PVERSION".tar.bz2 "$PNAME"-"$PVERSION";
# Copy the source tarball into the source directory for rpmbuild.
cp -pRP "$PNAME"-"$PVERSION".tar.bz2 ~/rpmbuild/SOURCES/;
# Generate the spec file.
m4 -D "PACKAGE_VERSION=""$PVERSION" -D "PREFIX=/usr" -D "SOURCE_TARBALL_NAME="$PNAME"-""$PVERSION"".tar.bz2" < "$PNAME"-"$PVERSION"/packaging/redhat/m4/rpm.spec > "$PNAME"-""$PVERSION"".spec ;
# Build the packages.
rpmbuild -ba --nodeps "$PNAME"-""$PVERSION"".spec;

