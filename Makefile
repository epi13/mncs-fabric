.PHONY: check test example

check: test
	python -m compileall -q src


test:
	python -m unittest discover -s tests -v


example:
	mkdir -p build
	mncs-fabric artifacts verify examples/portable-python/bundle examples/portable-python/artifact-manifest.json
	mncs-fabric plan validate examples/portable-python/job-plan.json
	mncs-fabric run local examples/portable-python/job-plan.json --root examples/portable-python/bundle --manifest examples/portable-python/artifact-manifest.json --label local-example --output build/example-record.json --results-dir build/results
	mncs-fabric reconcile build/example-record.json --output build/example-cohort.json
