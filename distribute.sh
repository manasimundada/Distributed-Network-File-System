#!/bin/bash

func() {
    cp -rf cp_folder/* $1
}

mkdir cp_folder
cp -rf *.c cp_folder/

func "ns_folder"
func "client_folder"
func "ss0"
func "ss1"
func "ss2"

rm -rf cp_folder