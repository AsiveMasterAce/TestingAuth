﻿namespace RealCreate.Web2.Services
{
    public interface ICookieService
    {
        string Get(string key);
        void Set(string key, string value);
        void Remove(string key);
    }
}
