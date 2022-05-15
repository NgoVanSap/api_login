<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Carbon\Carbon;
class AuthController extends Controller
{
    public $successStatus = 200;
    public function register(Request $request)
    {

        $rules = [
            'name' => 'unique:users|required',
            'email'    => 'unique:users|required',
            'password' => 'required',
        ];

        $input     = $request->only('name', 'email','password');
        $validator = Validator::make($input, $rules);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'error' => $validator->messages()]);
        }
        $name = $request->name;
        $email    = $request->email;
        $password = $request->password;
        $user     = User::create(['name' => $name, 'email' => $email, 'password' => Hash::make($password)]);

        if($user) {
            return response()->json([
                'success' => 'Register Thành công!',
            ]);
        }
    }

    public function login(Request $request){
        if(Auth::attempt(['email' => request('email'), 'password' => request('password')])){
            $user = Auth::user();
            $tokenResult =  $user->createToken('MyApp')->accessToken;
            return response()->json([
                '_token' => $tokenResult->token,
                'user' =>Auth::user(),
            ]);
        }
        else{
            return response()->json(['error'=>'Tài khoản hoặc mật khẩu sai!'], 401);
        }

    }
}
