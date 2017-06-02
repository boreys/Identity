using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.AspNetCore.Identity.Service
{
    public interface IDataSerializer<TModel>
    {
        byte[] Serialize(TModel model);
        TModel Deserialize(byte[] data);
    }
}
