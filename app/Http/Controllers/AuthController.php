<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
//
    public function showRegistrationForm()
    {
        return view('auth.register');
    }
    
    public function register(Request $request)
    {
    // $email = 'user@domain.com';
        if($request->generate_email || ($request->email && $request->generate_email)){
            $email = fake()->unique()->safeEmail();
                } else {
                            $email = $request->email;
                       }
                        $request->validate([
                            'name' => 'required|string|max:255|unique:users',
                            'password' => 'required|string|min:8|confirmed',
                        ]);
        User::create([
                        'name' => $request->name,
                        'email' => $email,
                        'password' => Hash::make($request->password),
                    ]);
                    return redirect()->route('login');
                    }
                        public function showLoginForm()
                    {
                    return view('auth.login');
                    }
                        public function login(Request $request)
                    {
                    $credentials = $request->validate([
                                                        'name' => 'required|string',
                                                        'password' => 'required|string',
                                                    ]);
                            if (Auth::attempt($credentials)) {
                                    $request->session()->regenerate();
                                    return redirect()->intended('/home');
                                }
                                return back()->withErrors([
                                        'username' => 'The provided credentials do not match our records.',
                                    ]);
                                }
    
    public function logout(Request $request)
    {
        Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
                return redirect()->route('login');
    }
}