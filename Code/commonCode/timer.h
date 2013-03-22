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
#include <vector>
#include <cstdio>

using std::vector;

// a class for performing timer measurements. The usage is as follows:
// 
// timer someTimer;
// int i = 0;
// while(i < 10) {
//     someTimer.Start();
//     .. code to measure ..
//     someTimer.Stop();
//     .. other code as needed ..
//     i++;
// }
// const vector<double>& m = someTimer.GetMeasurements();
// .. compute avg, std, or whatever ..
//
// A timer will throw if Start/Stop are called out of sequence, or if
// GetMeasurements is called while the timer is started but not stopped.
class timer {
  public:
    timer() : m_start(), m_stop(), 
        m_started(false), m_stopped(true),
        m_measurements() 
    { }

    inline void Start() {
        m_stopped = false;
        m_started = gettimeofday(&m_start, NULL) == 0;
        if (!m_started) throw "Coud not start timer\n";
    }

    inline void Stop() {
        m_started = false;
        m_stopped = gettimeofday(&m_stop, NULL) == 0;
        if (!m_stopped) throw "Coud not stop timer\n";

        struct timeval diff;
        timersub(&m_stop, &m_start, &diff);
        m_measurements.push_back(diff.tv_sec * 1000000.0 + diff.tv_usec);
    }

    inline const vector<double>& GetMeasurements() { 
        return m_measurements; 
    }

    inline void print(FILE* log) {
        vector<double>::iterator it = m_measurements.begin();
        fprintf(log, "[");
        bool first = true;
        for( ; m_measurements.end() != it; ++it) {
            if (!first) fprintf(log, ", ");
            first = false;
            fprintf(log, "%lf", *it);
        }
        fprintf(log, "]\n");
    }

    inline void Clear() {
        m_measurements.clear();
    }

  private:
    struct timeval m_start;
    struct timeval m_stop;
    bool m_started, m_stopped;
    vector<double> m_measurements;

    // disable copy and assignment
    timer(const timer&);
    timer& operator=(const timer&); 
};

#endif /* ndef _TIMER__H */
