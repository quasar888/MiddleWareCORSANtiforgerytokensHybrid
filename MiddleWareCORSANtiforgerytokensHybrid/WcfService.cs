using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel.Activation;
using System.Text;
using System.Threading.Tasks;

namespace MiddleWareCORSANtiforgerytokensHybrid
{
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    public class WcfService : IWcfService
    {
        public string GetData()
        {
            return "Hello from WCF (CORS + Anti-Forgery)";
        }

        public string PostData(string input)
        {
            // Validate anti-forgery token (if needed)
            return $"You sent: {input}";
        }
    }
}
