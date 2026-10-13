using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Text;

namespace Network_Analyzer
{
    internal class TimeLine
    {
        DateTime startTime;
        DateTime endTime;
        TimeSpan duration;
        TimeSpan interval;
  

        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get { return EndTime - StartTime; } }

        public TimeSpan Interval { get { return Duration / 10; } }

    }
}
