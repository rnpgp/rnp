# Test Case Guidelines for `rnp`

The document aims to describe and capture various use cases for `rnp` in
the form of the test cases. These can be used as acceptance tests for
the maintenance of the project.


## Naming conventions

The test case name is composed of the three parts.

* First being the module under test,
* Second being the feature and third details the motivation of the test.

Naming structure looks like: `<module>_<component>_<test-motivation>`.

For example, when testing the `generatekey` feature of `rnpkeys`, the
test case name would be `rnpkeys.generatekey.<test-motivation>`.


## Test Case Specification Template

The following template **SHOULD** be used for describing a test case.


~~~~~~ md
# <test-case-name>

Component
: <component-name>

Feature
: <feature-name>

## Objective

% Objective of test case

## Description

% Describe test case briefly

## Preconditions

% List of conditions prior to testing

* condition 1
* condition 2
* condition 3

## Test steps and expected behavior

1. Test step 1

1. Test step 2

Expectation: expectation here

## Verification steps and logic

1. Verification step 1
  * Rationale: verification logic

1. Verification step 2
  * Rationale: verification logic

## Comments

% if any

~~~~~~

