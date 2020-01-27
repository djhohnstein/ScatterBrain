using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ServiceManager
{
    class ServiceInformation
    {
        public string ServiceName { get; set; }
        public string[] SupportedOperatingSystems { get; set; }
        public string DLLPath { get; set; }
    }
}
