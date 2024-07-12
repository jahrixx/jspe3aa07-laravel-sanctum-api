@extends('mainLayout')
@section('page-title','Main Landing Page')
@section('page-content')

<h1>Welcome to the Site</h1>
    <br>
        {{-- <a href="{{ route('logout') }}">Logout</a> --}}
            <form action="{{ route('logout') }}">
            @csrf
                <button type="submit">Logout</button>
            </form>
@endsection