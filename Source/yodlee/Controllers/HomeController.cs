using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Mvc;

namespace yodlee.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {                        
            String dev_path = @"F:\2020-03\rsakey.pem";
            FileInfo file = new FileInfo(dev_path);            
            String token = CreateToken(file, "0098e798-63d6ffac-ee1e-4b68-9947-b42512985bf0", null);
            ViewBag.token = token;
            return View();
        }



        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }


        private long ToUnixTimestamp(DateTime date)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var time = date.ToUniversalTime().Subtract(epoch);
            return time.Ticks / TimeSpan.TicksPerSecond;
        }


        private String CreateToken(FileInfo key, string issuerId, string username)
        {

            long currentTime = ToUnixTimestamp(DateTime.Now) ;            
            var payload = new Dictionary<string, object>();

            payload["iss"] = issuerId;
            payload["iat"] = currentTime;
            payload["exp"] = currentTime + 1800;

            if (username != null)
            {
                payload["sub"] = username;
            }

            string token = CreateToken(payload, key);

            return token;
        }

        public  string CreateToken(Dictionary<string, object> payload, FileInfo privateKey)
        {
            RSAParameters rsaParams;

            using (var streamReader = privateKey.OpenText())
            {
                var pemReader = new PemReader(streamReader);

                RsaPrivateCrtKeyParameters privkey = null;
                Object obj = pemReader.ReadObject();

                if (obj != null)
                {
                    privkey = (RsaPrivateCrtKeyParameters)obj;
                }

                rsaParams = DotNetUtilities.ToRSAParameters(privkey);
         

            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);

                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS512);
            }
        }


        public ActionResult getToken()
        {
            String t = "";
            try
            {
                string id = Request["id"];
                String dev_path = @"F:\2020-03\rsakey.pem";
                FileInfo file = new FileInfo(dev_path);
                t = CreateToken(file, "0098e798-63d6ffac-ee1e-4b68-9947-b42512985bf0", id);
                
            }
            catch (Exception e)
            {
                return Json(new { result = 400, msg = e.ToString() }, JsonRequestBehavior.AllowGet);
            }

            return Json(new { result = 200, token = t }, JsonRequestBehavior.AllowGet);            

        }


    }
}