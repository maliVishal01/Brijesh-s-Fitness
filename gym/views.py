from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, logout, login
from .models import *
from .forms import *
from random import randint
from django.shortcuts import render
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404

def reset_password(request):
    reset_message = None
    if request.method == "POST" and "reset" in request.POST:
        email = request.POST.get("reset_email")
        new_password = request.POST.get("new_password")

        try:
            user = User.objects.get(email=email)
            user.password = make_password(new_password)  # ✅ hash the password
            user.save()
            reset_message = "Password changed successfully! You can now login."
        except User.DoesNotExist:
            reset_message = "Email not found. Please try again."

    return render(request, "user_login.html", {
        "show_reset_form": True,
        "reset_message": reset_message
    })


def contact_view(request):
    message = ''
    if request.method == 'POST':
        # Always use .get() to avoid MultiValueDictKeyError!
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        subject = request.POST.get('subject', '')
        user_message = request.POST.get('message', '')
        
        # Example simple validation
        if name and email and user_message:
            # Here you process/store/email the form data as required
            message = 'Your message has been sent successfully!'
        else:
            message = 'Please fill all required fields.'

    # Render the template with feedback message
    return render(request, 'contact.html', {'message': message})
def index(request):
    if request.method == "POST":
        u = request.POST['uname']
        p = request.POST['pwd']
        user = authenticate(username=u, password=p)
        if user:
            if user.is_staff:
                login(request, user)
                messages.success(request, "Logged In Successfully")
                return redirect('admin_home')
            else:
                messages.success(request, "Invalid Credentials, Please try again")
                return redirect('index')
    package = Package.objects.filter().order_by('id')[:5]
    return render(request, 'index.html', locals())


def registration(request):
    if request.method == "POST":
        fname = request.POST['firstname']
        lname = request.POST['secondname']
        email = request.POST['email']
        pwd = request.POST['password']
        mobile = request.POST['mobile']
        address = request.POST['address']

        # ------------------ CRITICAL FIX ------------------
        # Check if a user with this email (which is used as username) already exists
        if User.objects.filter(username=email).exists():
            messages.error(request, "Registration failed: A user with this email already exists.")
            return redirect('registration') 
        # ---------------------------------------------------

        try:
            # 1. Create the Django User account
            user = User.objects.create_user(
                first_name=fname, 
                last_name=lname, 
                email=email, 
                password=pwd, 
                username=email # Username MUST be unique
            )
            
            # 2. Create the linked Signup profile
            Signup.objects.create(user=user, mobile=mobile, address=address)
            
            messages.success(request, "Register Successful! Please log in now.")
            return redirect('user_login')
            
        except Exception as e:
            # Catch other potential database errors (e.g., integrity issues with the Signup model)
            messages.error(request, f"An unexpected error occurred during registration: {e}")
            return redirect('registration')
            
    return render(request, 'registration.html', locals())

# In gym/views.py

def user_login(request):
    if request.method == "POST":
        
        # --- A. Check for Password Reset Action ---
        # The Reset form contains 'action' or a button named 'reset'
        if 'reset' in request.POST or request.POST.get('action') == 'reset_password':
            # This logic should be moved to a separate reset_password view for better organization, 
            # but for now, we handle it here:
            
            reset_email = request.POST.get('reset_email')
            new_pwd = request.POST.get('new_password')
            
            if reset_email and new_pwd:
                try:
                    user_to_reset = User.objects.get(username=reset_email, is_staff=False)
                    user_to_reset.set_password(new_pwd)
                    user_to_reset.save()
                    messages.success(request, "Password reset successful. Please log in.")
                    return redirect('user_login')
                except User.DoesNotExist:
                    messages.error(request, "Error: Email ID not found.")
                    # Pass context back to show the reset form again
                    return render(request, 'user_login.html', {'show_reset_form': True, 'reset_message': "Error: Email ID not found."})
            
        # --- B. Check for Standard Login Action ---
        # The standard login form contains 'email'
        if 'email' in request.POST and 'password' in request.POST:
            email = request.POST['email']
            pwd = request.POST['password']
            user = authenticate(username=email, password=pwd)

            if user:
                if user.is_staff:
                    messages.error(request, "Invalid User (Admin accounts should use the Admin Login)")
                    return redirect('user_login')
                else:
                    login(request, user)
                    messages.success(request, "User Login Successful")
                    return redirect('index')
            else:
                messages.error(request, "Invalid Email or Password")
                return redirect('user_login')
        
    return render(request, 'user_login.html', locals())

def admin_home(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    totalcategory = Category.objects.all().count()
    totalpackagetype = Packagetype.objects.all().count()
    totalpackage = Package.objects.all().count()
    totalbooking = Booking.objects.all().count()
    New = Booking.objects.filter(status="1")
    Partial = Booking.objects.filter(status="2")
    Full = Booking.objects.filter(status="3")
    return render(request, 'admin/admin_home.html', locals())

def Logout(request):
    logout(request)
    messages.success(request, "Logout Successfully")
    return redirect('index')

def user_logout(request):
    logout(request)
    messages.success(request, "Logout Successfully")
    return redirect('index')

@login_required(login_url='user_login')
def user_profile(request):
    """
    Handles viewing and updating user profile details, safely fetching Signup data.
    """
    if request.method == "POST":
        # [Keep all your existing POST handling code here]
        fname = request.POST.get('firstname')
        lname = request.POST.get('secondname')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        address = request.POST.get('address')

        User.objects.filter(id=request.user.id).update(first_name=fname, last_name=lname, email=email, username=email)
        Signup.objects.filter(user=request.user).update(mobile=mobile, address=address)
        messages.success(request, "Updation Successful")
        return redirect('user_profile')
    
    # ------------------ CRITICAL FIX ------------------
    try:
        # Safely attempt to get the custom profile data
        data = Signup.objects.get(user=request.user)
    except Signup.DoesNotExist:
        # If the record is missing, send an error and redirect to the homepage
        messages.error(request, "Profile data is missing. Please contact support to correct your account.")
        return redirect('index') 
    # ---------------------------------------------------
        
    return render(request, "user_profile.html", locals())
def user_change_password(request):
    if request.method=="POST":
        n = request.POST['pwd1']
        c = request.POST['pwd2']
        o = request.POST['pwd3']
        if c == n:
            u = User.objects.get(username__exact=request.user.username)
            u.set_password(n)
            u.save()
            messages.success(request, "Password changed successfully")
            return redirect('/')
        else:
            messages.success(request, "New password and confirm password are not same.")
            return redirect('user_change_password')
    return render(request,'user_change_password.html')

def manageCategory(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.all()
    try:
        if request.method == "POST":
            categoryname = request.POST['categoryname']

            try:
                Category.objects.create(categoryname=categoryname)
                error = "no"
            except:
                error = "yes"
    except:
        pass
    return render(request, 'admin/manageCategory.html', locals())

def editCategory(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    error = ""
    category = Category.objects.get(id=pid)
    if request.method == "POST":
        categoryname = request.POST['categoryname']

        category.categoryname = categoryname

        try:
            category.save()
            error = "no"
        except:
            error = "yes"
    return render(request, 'admin/editCategory.html', locals())

def deleteCategory(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.get(id=pid)
    category.delete()
    return redirect('manageCategory')

@login_required(login_url='/admin_login/')
def reg_user(request):
    data = Signup.objects.all()
    d = {'data': data}
    return render(request, "admin/reg_user.html", locals())

@login_required(login_url='/admin_login/')
def delete_user(request, pid):
    data = Signup.objects.get(id=pid)
    data.delete()
    messages.success(request, "Delete Successful")
    return redirect('reg_user')

def managePackageType(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    package = Packagetype.objects.all()
    category = Category.objects.all()
    try:
        if request.method == "POST":
            cid = request.POST['category']
            categoryid = Category.objects.get(id=cid)

            packagename = request.POST['packagename']

            try:
                Packagetype.objects.create(category=categoryid, packagename=packagename)
                error = "no"
            except:
                error = "yes"
    except:
        pass
    return render(request, 'admin/managePackageType.html', locals())

def editPackageType(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.all()
    package = Packagetype.objects.get(id=pid)
    if request.method == "POST":
        cid = request.POST['category']
        categoryid = Category.objects.get(id=cid)
        packagename = request.POST['packagename']

        package.category = categoryid
        package.packagename = packagename

        try:
            package.save()
            error = "no"
        except:
            error = "yes"
    return render(request, 'admin/editPackageType.html', locals())


def deletePackageType(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    package = Packagetype.objects.get(id=pid)
    package.delete()
    return redirect('managePackageType')

def addPackage(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.all()
    packageid = request.GET.get('packagename', None)
    mypackage = None
    if packageid:
        mypackage = Packagetype.objects.filter(packagename=packageid)
    if request.method == "POST":
        cid = request.POST['category']
        categoryid = Category.objects.get(id=cid)
        packagename = request.POST['packagename']
        packageobj = Packagetype.objects.get(id=packagename)
        titlename = request.POST['titlename']
        duration = request.POST['duration']
        price = request.POST['price']
        description = request.POST['description']

        try:
            Package.objects.create(category=categoryid,packagename=packageobj,
                                   titlename=titlename, packageduration=duration,price=price,description=description)
            error = "no"
        except:
            error = "yes"
    mypackage = Packagetype.objects.all()
    return render(request, 'admin/addPackage.html',locals())

def managePackage(request):
    package = Package.objects.all()
    return render(request, 'admin/managePackage.html',locals())

@login_required(login_url='/user_login/')
def booking_history(request):
    data = Signup.objects.get(user=request.user)
    data = Booking.objects.filter(register=data)
    return render(request, "booking_history.html", locals())

@login_required(login_url='/admin_login/')
def new_booking(request):
    action = request.GET.get('action')
    data = Booking.objects.filter()
    if action == "New":
        data = data.filter(status="1")
    elif action == "Partial":
        data = data.filter(status="2")
    elif action == "Full":
        data = data.filter(status="3")
    elif action == "Total":
        data = data.filter()
    if request.user.is_staff:
        return render(request, "admin/new_booking.html", locals())
    else:
        return render(request, "booking_history.html", locals())


def booking_detail(request, pid):
    data = Booking.objects.get(id=pid)
    if request.method == "POST":
        price = request.POST['price']
        status = request.POST['status']
        data.status = status
        data.save()
        Paymenthistory.objects.create(booking=data, price=price, status=status)
        messages.success(request, "Action Updated")
        return redirect('booking_detail', pid)
    payment = Paymenthistory.objects.filter(booking=data)
    if request.user.is_staff:
        return render(request, "admin/admin_booking_detail.html", locals())
    else:
        return render(request, "user_booking_detail.html", locals())

def editPackage(request, pid):
    category = Category.objects.all()
    if request.method == "POST":
        cid = request.POST['category']
        categoryid = Category.objects.get(id=cid)
        packagename = request.POST['packagename']
        packageobj = Packagetype.objects.get(id=packagename)
        titlename = request.POST['titlename']
        duration = request.POST['duration']
        price = request.POST['price']
        description = request.POST['description']

        Package.objects.filter(id=pid).update(category=categoryid,packagename=packageobj,
                                   titlename=titlename, packageduration=duration,price=price,description=description)
        messages.success(request, "Updated Successful")
        return redirect('managePackage')
    data = Package.objects.get(id=pid)
    mypackage = Packagetype.objects.all()
    return render(request, "admin/editPackage.html", locals())

def load_subcategory(request):
    categoryid = request.GET.get('category')
    subcategory = Package.objects.filter(category=categoryid).order_by('PackageName')
    return render(request,'subcategory_dropdown_list_options.html',locals())

def deletePackage(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    package = Package.objects.get(id=pid)
    package.delete()
    return redirect('managePackage')

def deleteBooking(request, pid):
    booking = Booking.objects.get(id=pid)
    booking.delete()
    messages.success(request, "Delete Successful")
    return redirect('new_booking')

def bookingReport(request):
    data = None
    data2 = None
    if request.method == "POST":
        fromdate = request.POST['fromdate']
        todate = request.POST['todate']

        data = Booking.objects.filter(creationdate__gte=fromdate, creationdate__lte=todate)
        data2 = True
    return render(request, "admin/bookingReport.html", locals())

def regReport(request):
    data = None
    data2 = None
    if request.method == "POST":
        fromdate = request.POST['fromdate']
        todate = request.POST['todate']

        data = Signup.objects.filter(creationdate__gte=fromdate, creationdate__lte=todate)
        data2 = True
    return render(request, "admin/regReport.html", locals())


def changePassword(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    error = ""
    user = request.user
    if request.method == "POST":
        o = request.POST['oldpassword']
        n = request.POST['newpassword']
        try:
            u = User.objects.get(id=request.user.id)
            if user.check_password(o):
                u.set_password(n)
                u.save()
                error = "no"
            else:
                error = 'not'
        except:
            error = "yes"
    return render(request, 'admin/changePassword.html',locals())

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

# @login_required(login_url='/user_login/')
# def booking(request):
#     booking = None
#     bookinged = Booking.objects.filter(register__user=request.user)
#     bookinged_list = [i.policy.id for i in bookinged]
#     data = Package.objects.filter().exclude(id__in=bookinged_list)
#     if request.method == "POST":
#         booking = Package.objects.filter()
#         booking = BookingForm(request.POST, request.FILES, instance=booking)
#         if booking.is_valid():
#             booking = booking.save()
#             booking.bookingnumber = random_with_N_digits(10)
#             data.booking = booking
#             data.save()
#         Booking.objects.create(package=booking)
#         messages.success(request, "Action Updated")
#         return redirect('booking')
#     return render(request, "/", locals())

@login_required(login_url='/user_login/')
def apply_booking(request, pid):
    data = Package.objects.get(id=pid)
    register = Signup.objects.get(user=request.user)
    booking = Booking.objects.create(package=data, register=register, bookingnumber=random_with_N_digits(10))
    messages.success(request, 'Booking Applied')
    return redirect('/')

@login_required(login_url='index')
def create_missing_profile(request, user_id):
    if not request.user.is_staff:
        return redirect('index')
        
    user_to_fix = get_object_or_404(User, id=user_id)
    
    if not hasattr(user_to_fix, 'signup'): # Checks if the related Signup object exists
        # Create a basic profile with placeholder/blank data
        Signup.objects.create(
            user=user_to_fix, 
            mobile='0000000000', 
            address='Profile Created by Admin'
        )
        messages.success(request, f"Profile created for {user_to_fix.email}.")
    else:
        messages.warning(request, f"Profile already exists for {user_to_fix.email}.")

    return redirect('reg_user') # Redirect back to registered user list