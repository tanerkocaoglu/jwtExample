using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jwtExample.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly string signingKey = "SigningKeyiminSakladigiAlanBurasi";

		[HttpGet]
		public string Get(string userName, string password)
		{
			var claims = new[]
			{
				new Claim(ClaimTypes.Name,userName),
				new Claim(JwtRegisteredClaimNames.Email,userName)
			};

			var securtiyKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
			var credentials = new SigningCredentials(securtiyKey, SecurityAlgorithms.HmacSha256);

			var jwtSecurityToken = new JwtSecurityToken(
				audience: "BenimAudienceDegeri",
				claims: claims,
				expires: DateTime.Now.AddDays(15),
				notBefore: DateTime.Now,
				signingCredentials: credentials
			);

			var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

			return token;
		}

		[HttpGet("ValidateToken")]

		public bool ValidateToken(string token)
		{
			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
			try
			{
				JwtSecurityTokenHandler handler = new();
				handler.ValidateToken(token, new TokenValidationParameters()
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = securityKey,
					ValidateLifetime = true,
					ValidateAudience = false,
					ValidateIssuer = false,
				}, out SecurityToken validatedToken);
				var jwtToken = (JwtSecurityToken)validatedToken;
				var claims = jwtToken.Claims.ToList();

				return true;
			}
			catch (Exception)
			{
				return false;
			}
		}
	}
}
