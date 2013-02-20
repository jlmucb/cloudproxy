//
//  timer.h
//      Tom Roeder
//
//  Description: a class for performing timing measurements
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the 
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


// ----------------------------------------------------------------------------

#ifndef _TIMER__H
#define _TIMER__H

#include <sys/time.h>

// a class for performing timer measurements. The usage is as follows:
// 
// timer someTimer;
// someTimer.Start();
// .. code to measure ..
// someTimer.Stop();
// .. other code as needed ..
// double microseconds = someTimer.GetInterval();
//
// A timer will throw an exception if GetInteval() is called before Start()
// and Stop() have been called.
class timer {
 public:
  timer() : m_start(), m_stop(), m_started(false), m_stopped(false) { }
  inline void Start() {
      m_started = gettimeofday(&m_start, NULL) == 0;
      if (!m_started) throw "Coud not start timer\n";
  }

  inline void Stop() {
      m_stopped = gettimeofday(&m_stop, NULL) == 0;
      if (!m_stopped) throw "Coud not stop timer\n";
  }

  inline double GetInterval() {
    if (!m_started || !m_stopped) throw "Timer not started\n";
    struct timeval diff;
    timersub(&m_stop, &m_start, &diff);
    return diff.tv_sec * 1000000.0 + diff.tv_usec;
  }
 private:
  struct timeval m_start;
  struct timeval m_stop;
  bool m_started, m_stopped;

  // disable copy and assignment
  timer(const timer&);
  timer& operator=(const timer&); 
};

#endif /* ndef _TIMER__H */
