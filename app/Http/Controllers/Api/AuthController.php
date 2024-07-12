<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;


class AuthController extends Controller
{
    //Add Register function 
    public function register(Request $request)
    {
        try {
            // Validation
            $validateUser = Validator::make($request->all(), [
                'name' => 'required|string|max:255|unique:users,name',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|string|min:8|confirmed',
            ]);
    
            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation Error',
                    'errors' => $validateUser->errors()
                ], 401);
            }
    
            // User creation
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
    
            // Token creation
            $token = $user->createToken("API Token")->plainTextToken;
    
            // Check if email generation is required
            if ($request->generate_email || ($request->email && $request->generate_email)) {
                $email = fake()->unique()->safeEmail();
            } else {
                $email = $request->email;
            }
    
            // Redirect to login page
            return redirect()->route('login')->with('token', $token);
    
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }

    //Login Function
    public function login(Request $request)
    {
        try {
            // Validate the request
            $validateUser = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'password' => 'required|string|min:8',
            ]);

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation Error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            // Attempt to log the user in
            if (!Auth::attempt(['name' => $request->name, 'password' => $request->password])) {
                return response()->json([
                    'status' => false,
                    'message' => 'Name & Password are not valid.'
                ], 401);
            }

            // Retrieve the authenticated user
            $user = Auth::user();

            // Generate the token for API
            $token = $user->createToken("API Token")->plainTextToken;

            // For API response
            if ($request->expectsJson()) {
                return response()->json([
                    'status' => true,
                    'message' => 'Login is successful!',
                    'token' => $token
                ], 200);
            }

            // For web login, regenerate session
            $request->session()->regenerate();

            return redirect()->intended('/home');

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }


    //Profile Function
    public function profile(){
        $userData = auth()->user();
        return response()->json([
            'status'=> true,
            'message' => 'This is user profile',
            'data' => $userData,
            'id' => auth()->user()->id
        ],200);
    }

    //Logout Function
    public function logout(Request $request){
        if (Auth::check()) {
            // For web logout
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
    
            return redirect()->route('login');
        } else if (auth()->user()) {
            // For API logout
            auth()->user()->tokens()->delete();
            return response()->json([
                'status' => true,
                'message' => 'User logout successfully!',
                'data' => []
            ], 200);
        }
    
        // In case no user is authenticated
        return response()->json([
            'status' => false,
            'message' => 'No user is authenticated!',
            'data' => []
        ], 401);
    }

    public function showLoginForm()
    {
        return view('auth.login');
    }

    public function showRegistrationForm()
    {
        return view('auth.register');
    }
}