#!/bin/sh

cp -fr pnr_server upgrade/

version=$(cat version)
tar -cjf ppr_${version}.tar.bz2 upgrade/*
