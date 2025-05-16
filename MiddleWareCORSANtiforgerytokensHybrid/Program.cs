using Microsoft.Owin.Hosting;
using MiddleWareCORSANtiforgerytokensHybrid;
using System;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Web;

class Program
{
    static void Main(string[] args)
    {
        // Start OWIN host (for CORS & Anti-Forgery)
        string baseAddress = "http://localhost:9000/";
        using (WebApp.Start<Startup>(url: baseAddress))
        {
            Console.WriteLine("OWIN host running...");

            // Start WCF service
            var wcfServiceHost = new WebServiceHost(typeof(WcfService), new Uri(baseAddress + "api"));
            wcfServiceHost.Open();

            Console.WriteLine("WCF service running...");
            Console.WriteLine("Press Enter to exit.");
            Console.ReadLine();

            wcfServiceHost.Close();
        }
    }
}