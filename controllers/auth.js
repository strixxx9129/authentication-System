const User=require('../models/User');
async function handleUserSignup(req,res){
    const {name,email,password} =req.body;
    await User.create({name,email,password});
    return res.render("home");
}
module.exports={handleUserSignup};