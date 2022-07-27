using ConsoleApp2.WinFirewall;
using System.Diagnostics;
using AIPDBAPI;
using System.Linq;
using System.Collections.Generic;
using System.Threading;

List<string> Flagged_ips = new List<string>();
List<string> displayed_ips = new List<string>();


static void BlockAtFireWall(string Ipaddy)
{
    ConsoleApp2.WinFirewall.FWCtrl.SetupBlockRule(Ipaddy);
}

static void ReportIP(string IP_ADDY)
{
    string API_KEY = "havetofixgot403";
    string IP = IP_ADDY;
    string COMMENTS = "Rdp Bruter";
    AIPDB.ReportIP(API_KEY, IP, COMMENTS, AIPDB.Categories.Brute_Force);
}


static string Extract_IP(string message)
{
    string ip_extracted = "";
    if (message.Contains("Source Network Address:"))
    {
        String tmp_word = $"{message}";
        String trim = tmp_word.Replace(" ", String.Empty);
        trim = trim.Replace("\t", "");
        String resulty = trim.Replace("SourceNetworkAddress:", "");
        ip_extracted = resulty.Replace(":", "");
        ip_extracted = resulty;



    }
    return ip_extracted;

}

static string Extract_user(string message)
{
    string user_attemted = "";
    if (message.Contains("Account Name:"))
    {
        
        String tmp_word = $"{message}";
        String trim = tmp_word.Replace(" ", String.Empty);
        trim = trim.Replace("\t", "");
        user_attemted = String.Concat(trim);
        String result = user_attemted.Replace("AccountName:", "");
        //result = result.Replace("-:", "");
        user_attemted = result.Replace("-", "");
      

    }
    return user_attemted;

}



 void ReadEvenLogBruteAttemptUsers()
{
    string eventLogName = "Security";
    
    EventLog eventLog = new EventLog();
    eventLog.Log = eventLogName;
    var entries = eventLog.Entries.Cast<EventLogEntry>()
                     .Where(x => x.TimeWritten >= DateTime.Now.AddMinutes(-10))
                     .ToList();

    List<string> BadIps = new List<string>();
    List<string> blockable = new List<string>();


    foreach (EventLogEntry log in entries)

    {
        String id_num = log.EventID.ToString();
  
        String Ip_Address = "";
    
        if (id_num.Contains("4625"))
        {
            string[] words = log.Message.Split('\n');
            
            foreach (var word in words)
            {
                //Console.WriteLine(word);

                //System.Console.WriteLine(word.ToString());
                string USerTried = Extract_user(word);
                if (!String.IsNullOrEmpty(USerTried))
                { 
                    Console.WriteLine(USerTried); 
                }
                   

                Ip_Address  = Extract_IP(word);
                if (!String.IsNullOrEmpty(Ip_Address))
                {
                    Console.WriteLine(Ip_Address);
                }
                bool IPalreadyExists = BadIps.Contains(Ip_Address.ToString());
                
                if (!IPalreadyExists)
                {
                    //Console.WriteLine(resulty.ToString());
                    bool alreadyExists = Flagged_ips.Contains(Ip_Address.ToString());
                    if (!alreadyExists)
                    {
                        Flagged_ips.Add(Ip_Address.ToString());
                    }
                }
           

            }

            


        }
  




    }
    foreach (var ips in Flagged_ips)
    {
        if (!String.IsNullOrEmpty(ips))
        {
            bool Exists = displayed_ips.Contains(ips.ToString());
            if (!Exists)
            {
                displayed_ips.Add(ips);
                Console.WriteLine(ips);
                BlockAtFireWall(ips);
            }

        }

        //firewall block
    }
}

while(true)
{
    Console.WriteLine("Working Checking for BRute Attempts ...");
    ReadEvenLogBruteAttemptUsers();

}



