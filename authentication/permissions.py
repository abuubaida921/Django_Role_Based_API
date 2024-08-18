from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'administrator'

class IsTeacher(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role in ['teacher', 'staff']
    
class IsStudent(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'student'
