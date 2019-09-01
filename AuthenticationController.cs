using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using VoyageTravelsAPI.VoyageTravels.Service.DTO;
using VoyageTravelsAPI.VoyageTravels.Data.Models;
using VoyageTravelsAPI.VoyageTravels.Service.Interface;
using Microsoft.Extensions.Configuration;

using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace VoyageTravelsAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
       private readonly IMapper _mapper;
       private Response _response;
       IAuthenticate _IAuthenticate ;
       IConfiguration _IConfiguration;
       public AuthenticationController(IMapper mapper, IAuthenticate IAuthenticate, IConfiguration IConfiguration)
       {
             _response = new Response();
            _mapper = mapper;
            _IAuthenticate = IAuthenticate;
            _IConfiguration = IConfiguration;
       } 

       
         [HttpPost("Login")]
        public IActionResult Login([FromBody] LoginParameters LoginParameters)
        {
           Users users = _mapper.Map<Users>(LoginParameters);
            try
            {
                if (LoginParameters == null)
                {
                    return BadRequest("Specified Object is null or empty");
                }

                 var claim = new[]{
                     new Claim(JwtRegisteredClaimNames.Sub, LoginParameters.MobileNumber)
                 };

                  _response = _IAuthenticate.AuthenticateUsers(users);


                 /*To get token first */
                  var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_IConfiguration["Jwt:SigningKey"]));
                 
                 int exPiryInMinute = Convert.ToInt32(_IConfiguration["Jwt:ExpiryInMinutes"]);

                 var token = new JwtSecurityToken(
                                issuer: _IConfiguration["Jwt:Site"],
                                audience:  _IConfiguration["Jwt:Site"],
                                expires: DateTime.UtcNow.AddMinutes(exPiryInMinute),
                                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                                 );
                    
                    return Ok(new {
                                token = new JwtSecurityTokenHandler().WriteToken(token),
                                expiration = token.ValidTo,
                                response = _response
                          });
                 
                 //return Ok(_response);
            }
            catch (Exception ex)
            {
                var exM =  ex == null ? ex.InnerException.Message : ex.Message;
                _response.ResponseCode = "99";
                _response.ResponseText = exM;
                 return Ok(_response); 
            }

            return BadRequest();
        }
        
    }
}
