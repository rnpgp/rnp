all: fedora35.pushed
clean:
	rm *.built *.pushed
.PHONY: all clean

fedora35.built:
	cd ../.. && docker build --squash -t andreyutkin/rnp-ci-fedora:35 -f ci/docker/fedora35.Dockerfile .
	touch $@
fedora35.pushed: fedora35.built
	docker push andreyutkin/rnp-ci-fedora:35
	touch $@
