#!/bin/sh

version=$(cat version)
tar -cjf ppr_${version}.tar.bz2 ppr/*
