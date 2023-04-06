FROM fedora:35
RUN dnf makecache
RUN dnf -y install \
autoconf \
automake \
bison \
botan2 \
botan2-devel \
byacc \
bzip2 \
bzip2-devel \
clang \
cmake \
gcc \
gcc-c++ \
gettext-devel \
git \
gtest \
gtest-devel \
gzip \
json-c \
json-c-devel \
libtool \
make \
ncurses-devel \
openssl \
openssl-devel \
openssl-libs \
python3 \
ruby-devel \
rubygem-asciidoctor \
sudo \
wget \
zlib-devel \
;
RUN dnf clean all

RUN useradd rnpuser
RUN echo -e "rnpuser\tALL=(ALL)\tNOPASSWD:\tALL" > /etc/sudoers.d/rnpuser
RUN echo -e "rnpuser\tsoft\tnproc\tunlimited\n" > /etc/security/limits.d/30-rnpuser.conf

# Everything below wouldn't be needed if packaged gpg didn't fail with "Unknown elliptic curve"
# on these tests from cli_tests.Misc:
# test_aead_last_chunk_zero_length
# test_clearsign_long_lines
# test_eddsa_sig_lead_zero
# test_text_sig_crcr

COPY ci ci
RUN export USE_STATIC_DEPENDENCIES=yes && su rnpuser -c ci/install_noncacheable_dependencies.sh
RUN export USE_STATIC_DEPENDENCIES=yes && su rnpuser -c ci/install_cacheable_dependencies.sh
RUN rm -rf /home/rnpuser/local-builds
