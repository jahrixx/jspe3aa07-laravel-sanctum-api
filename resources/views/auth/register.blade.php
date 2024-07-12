@extends('mainLayout')
@section('page-title','Account Registration')
@section('auth-content')

<form method="POST" action="{{ route('register') }}">
    @csrf
        <div>
            <label class="auth-labels">Username</label>
            <input type="text" name="name" value="{{ old('username') }}" required class="auth-textbox">
            @error('name')
                <span>{{ $message }}</span>
                @enderror
        </div>
        <div>
            <label class="auth-labels">Email</label>
            <input type="email" name="email" class="auth-textbox">
            <input type="checkbox" name="generate_email">Generate
            @error('email')
                <span>{{ $message }}</span>
                @enderror
        </div>
        <div>
            <label class="auth-labels">Password</label>
            <input type="password" name="password" required class="auth-textbox">
            @error('password')
                <span>{{ $message }}</span>
                @enderror
        </div>
        <div>
            <label class="auth-labels">Confirm Password</label>
            <input type="password" name="password_confirmation" required class="auth-textbox">
        </div>
        <button type="submit">Register</button>
</form>
@endsection