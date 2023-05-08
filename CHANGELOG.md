# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Updated review-database to 0.8.0-alpha.2. (TODO: update to 0.8.0 before release)

## [0.4.1] - 2023-05-05

### Added

- Added a GraphQL query, `rankedOutliers`, to retrieve outliers.

## [0.4.0] - 2023-05-04

### Changed

- Updated `review-database` to 0.7.1.

## [0.3.0] - 2023-05-02

### Changed

- Updated `ip2location` to 0.4.2.
- Updated `review-database` to 0.7.0.
- GraphQL API `columnStatistics`: This query's parameters have been modified to
  support event source.
  - Replaced separate firstEventId: Int and lastEventId: Int parameters with a
    single eventRange: EventRangeInput parameter.
  - EventRangeInput is a new input type that includes the following required
    fields:
    - firstEventId: !Int (equivalent to the previous firstEventId parameter).
    - lastEventId: !Int (equivalent to the previous lastEventId parameter).
    - eventSource: !String (a new required field indicating the source of the
      events).

## [0.2.0] - 2023-04-27

### Changed

- Added `port/procotol` to traffic filter rule to filter traffic in Piglet.

## [0.1.0] - 2023-04-24

### Added

- An initial version.

[Unreleased]: https://github.com/petabi/review-web/compare/0.4.1...main
[0.4.1]: https://github.com/petabi/review-web/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/petabi/review-web/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-web/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-web/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/petabi/review-web/tree/0.1.0
