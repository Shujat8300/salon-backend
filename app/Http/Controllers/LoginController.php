<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        try {
            $email = $request->email == null;
            if ($email) {
                return response()->json((['success' => false, 'message' => 'email field is required']));
            }
            $passwrod = $request->password == null;
            if ($passwrod) {
                return response()->json((['success' => false, 'message' => 'password field is required']));
            }
            // $check_passwrod =base64_decode($request->password);
            if (Auth::attempt(['email' => $request->email, 'password' => $request->password, 'role'=>'admin'])) {
                $user = Auth::user();

                // $success['token'] = $user->createToken('MyApp')->accessToken;
                $request = Request::create('oauth/token', 'POST', [
                    "grant_type" => "password",
                    "client_id" => "3",
                    "client_secret" => "RHRNs3jlSdA3vUiqscZmNW7HMRJq1uwDYzRIfVHf",
                    "username" => $request->email,
                    "password" => $request->password,
                    "scope" => "",
                ]);
                $result = app()->handle($request);
                $response = json_decode($result->getContent(), true);
                $success['token'] = $response['access_token'];
                $success['refreshToken'] = $response['refresh_token'];
                $success['id'] = $user->id;
                $success['name'] = $user->name;
                $success['email'] = $user->email;
                $success['role'] = $user->role;
                return response()->json(['success' => true, 'user' => $success]);
            } else {
                return response()->json(['success' => false, 'message' => 'Unauthorized access']);
            }
        } catch (Exception $e) {
            return response()->json(["success" => false, "error" => "internal Server error"], 500);
        }
    }
    //register
    public function register(Request $request)
    {
        if ($request->email == null) {
            return response()->json((['success' => false, 'message' => 'email field is required']));
        }
        if ($request->password == null) {
            return response()->json((['success' => false, 'message' => 'password field is required']));
        }
        if ($request->name == null) {
            return response()->json((['success' => false, 'message' => 'name field is required']));
        }
        $check = User::where('email', '=', $request->email)->first();
        if ($check) {
            return response()->json((['success' => false, 'message' => 'this email is already registered']));
        }
        $data = new User();
        $data->name = $request->name;
        $data->password = Hash::make($request->password);
        $data->email = $request->email;
        $data->p = encrypt($request->password);
        $data->role = 'admin';
        $data->save();
        return response()->json((['success' => true, 'message' => 'registered successfully']));

    }
    public function refreshToken(Request $request)
    {
        try {
            if($request->refreshToken == null)
            {
                return response()->json((['success' => false, 'message' => 'refreshToken is required']));
            }
            $request = Request::create('oauth/token', 'POST', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $request->refreshToken,
                'client_id' => '3',
                'client_secret' => "RHRNs3jlSdA3vUiqscZmNW7HMRJq1uwDYzRIfVHf",
                'scope' => '',
            ]);
            $result = app()->handle($request);
            $response = json_decode($result->getContent(), true);
            if (array_key_exists('error', $response)) {
                return response()->json(['success' => false, 'token' => $response]);
            } else {
                $user = User::find(Auth::guard('api')->user()->id);
                $success['token'] = $response['access_token'];
                $success['refreshToken'] = $response['refresh_token'];
                $success['id'] = $user->id;
                $success['name'] = $user->name;
                $success['email'] = $user->email;
                return response()->json(['success' => true, 'user' => $success]);
            }
        } catch (Exception $e) {
            return response()->json(["success" => false, "error" => "internal Server error"], 500);
        }
    }
    //loginCheck
    public function loginCheck()
    {
        try {
            logger(Auth::guard('api')->user()); // to get user
            $user = Auth::guard('api')->user();
            $password = decrypt($user->p);
            $request = Request::create('oauth/token', 'POST', [
                "grant_type" => "password",
                "client_id" => "3",
                "client_secret" => "RHRNs3jlSdA3vUiqscZmNW7HMRJq1uwDYzRIfVHf",
                "username" => $user->email,
                "password" => $password,
                "scope" => "",
            ]);
            $result = app()->handle($request);
            $response = json_decode($result->getContent(), true);
            $success['token'] = $response['access_token'];
            $success['refreshToken'] = $response['refresh_token'];
            $success['id'] = $user->id;
            $success['name'] = $user->name;
            $success['email'] = $user->email;
            return response()->json(['success' => true, 'user' => $success]);
        } catch (Exception $e) {
            return response()->json(["success" => false, "message" => "internal Server error"], 500);
        }
    }

    //updateProfile
    public function updateProfile(Request $request)
    {
        try {

            $name = $request->name == null;
            if ($name) {
                return response()->json((['success' => false, 'message' => 'name field is required']));
            }
            $email = $request->email == null;
            if ($email) {
                return response()->json((['success' => false, 'message' => 'email field is required']));
            }
            $check = User::where([['id', '!=', Auth::guard('api')->user()->id], ['email', '=', $request->email]])->first();
            if ($check) {
                return response()->json((['success' => false, 'message' => 'email already registerd']));
            }
            $data = User::find(Auth::guard('api')->user()->id);
            if ($data == null) {
                return response()->json((['success' => false, 'message' => 'User not fund']));
            } else {
                $data->name = $request->name;
                $data->email = $request->email;
                $data->save();
                return response()->json((['success' => true, 'message' => 'profile updated successfully !!']));

            }

        } catch (Exception $e) {
            return response()->json(["success" => false, "error" => "internal Server error"], 500);
        }
    }
    //changePassword
    public function changePassword(Request $request)
    {

        if ($request->oldPassword == null) {
            return response()->json(["success" => false, "message" => "old Password is required !!"]);
        }
        if ($request->newPassword == null) {
            return response()->json(["success" => false, "message" => "new Password is required !!"]);
        }
        $user = User::find(Auth::guard('api')->user()->id);
        if ($user == null) {
            return response()->json(["success" => false, "message" => "no record found !!"]);
        }
        if (Hash::check($request->newPassword, $user->password)) {
            return response()->json(["success" => false, "message" => "new password can not be your old password"]);
        }
        if (Hash::check($request->oldPassword, $user->password)) {
            $password = $request->newPassword;
            $min_length = 8;
            if (strlen($password) >= $min_length &&
                preg_match('/[A-Z]/', $password) &&
                preg_match('/[0-9]/', $password) &&
                preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) {
                // Password meets the requirements
                $newPassword = bcrypt($password);
            } else {
                return response()->json(['success' => false, 'message' => 'password should container mininum 8 characters, one uppercase, one number, one special character']);
            }
            $user->password = $newPassword;
            $user->p = encrypt($request->password);
            $user->save();
            return response()->json(["success" => true, "message" => "Password Changed Successfully !!"]);
        } else {
            return response()->json(["success" => false, "message" => "Invalid old Password!!"]);
        }
    }

    //logout
    public function logout(Request $request)
    {
        try {
            $user = Auth::guard('api')->user();
            $user->token()->revoke();
            return response()->json(['success' => true, 'message' => 'logout successfully']);
        } catch (Exception $e) {
            return response()->json(["success" => false, "message" => "internal Server error"], 500);
        }
    }

}
