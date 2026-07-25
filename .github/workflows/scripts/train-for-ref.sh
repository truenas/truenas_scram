#!/usr/bin/env bash

######################################################################
# Map a git ref (branch name) to the TrueNAS train whose rolling
# <train>-nightly deb release this repo publishes to.
#
#   train-for-ref.sh REF
#
# REF - branch name, e.g. master, stable/26, or a pull request base ref.
#
# Prints the train name (master or 26) on stdout.  This is the single
# source of truth for the branch -> train mapping, and mirrors the
# mapping used by the other TrueNAS repos publishing rolling debs
# (truenas/zfs, truenas/linux, truenas/truenas_pylibzfs).
######################################################################

set -eu

REF="${1:-}"

case "$REF" in
  stable/26) echo "26" ;;
  *)         echo "master" ;;
esac
