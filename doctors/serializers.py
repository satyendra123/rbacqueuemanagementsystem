from rest_framework import serializers
from .models import Department, Doctor

class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'

class DoctorSerializer(serializers.ModelSerializer):
    department_name = serializers.ReadOnlyField(source='department.name')

    class Meta:
        model = Doctor
        fields = ['id', 'name', 'specialty', 'department', 'department_name', 'availability', 'opd_no', 'created_at', 'updated_at']

    def validate_department(self, value):
        """Ensure the provided department exists before allowing doctor creation."""
        if not Department.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Invalid department. Please provide a valid department ID.")
        return value
