#!/bin/sh

version=$(cat gqlcnode_version)
tar -cjf gqlcnode_${version}.tar.bz2 gqlcnode_upgrade/*
