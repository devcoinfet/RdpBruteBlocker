using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp2
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    using NetFwTypeLib;

    namespace WinFirewall
    {
        internal class FWCtrl
        {
            const string guidFWPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
            const string guidRWRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";




            public static  void SetupBlockRule(String ipaddy)
            {
                Type typeFWPolicy2 = Type.GetTypeFromCLSID(new Guid(guidFWPolicy2));
                Type typeFWRule = Type.GetTypeFromCLSID(new Guid(guidRWRule));
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);
                INetFwRule newRule = (INetFwRule)Activator.CreateInstance(typeFWRule);
                newRule.Name = "InBound_Rule_rdp_blocked_"+ ipaddy.Trim();
                newRule.Description = "Block inbound traffic from ipaddy over TCP port 3389";
                newRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                newRule.LocalPorts = "3389";
                newRule.RemoteAddresses = ipaddy.Trim();
                newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                newRule.Enabled = true;
                newRule.Grouping = "@firewallapi.dll,-23255";
                newRule.Profiles = fwPolicy2.CurrentProfileTypes;
                newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                fwPolicy2.Rules.Add(newRule);

            }
        }
    }
}
